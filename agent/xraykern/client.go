// Package xraykern is the agent's client of the locally installed Xray kernel
// (the W1nCray-xray program). It implements agent/xrayapi.Service without
// linking Xray-core:
//
//   - Status reads the kernel's local status endpoint (a Unix socket, or the
//     loopback address file on Windows);
//   - CheckStaged runs the installed kernel binary's own check-staged command,
//     so the agent validates a staged managed-file set with exactly the loader
//     the running instance uses;
//   - WaitReloaded waits until the kernel reports the content fingerprint of
//     the files that were just written.
//
// A machine without the kernel degrades safely: every method returns the
// explicit "Xray 内核未安装" error instead of half-applying a file set no
// instance would read.
package xraykern

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/xrayapi"
)

// ErrNotInstalled is returned by every method when no version of the Xray
// kernel is installed on this machine.
var ErrNotInstalled = errors.New("Xray 内核未安装")

// CurrentKernel resolves the installed current version of a kernel. The
// production implementation is *kernelx.Ensurer.
type CurrentKernel interface {
	Current(name string) (driver.Installed, error)
}

// Runner runs one external command and returns its combined output. It is an
// argv array, never a shell.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// ExecRunner runs commands with os/exec.
type ExecRunner struct{}

// Run implements Runner.
func (ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// Defaults.
const (
	DefaultStatusTimeout = 2 * time.Second
	DefaultReloadTimeout = 30 * time.Second
	DefaultPollInterval  = 500 * time.Millisecond
	// maxStatusBytes bounds what is read from the status endpoint.
	maxStatusBytes = 1 << 20
)

// Options configures a Client. ConfigPath and Kernels are required.
type Options struct {
	// ConfigPath is the absolute path of config.yml: the status endpoint lives
	// next to it and check-staged is run against it.
	ConfigPath string
	// Kernels resolves the installed current kernel binary.
	Kernels CurrentKernel
	// Runner executes the kernel binary (default ExecRunner).
	Runner Runner
	// StatusTimeout bounds one status request (default 2s).
	StatusTimeout time.Duration
	// ReloadTimeout bounds WaitReloaded (default 30s).
	ReloadTimeout time.Duration
	// PollInterval is how often WaitReloaded re-reads the status (default
	// 500ms).
	PollInterval time.Duration
}

// Client implements xrayapi.Service against the local kernel.
type Client struct {
	opts Options
}

var _ xrayapi.Service = (*Client)(nil)

// New builds a Client.
func New(o Options) (*Client, error) {
	if o.ConfigPath == "" {
		return nil, errors.New("xraykern: ConfigPath is required")
	}
	if o.Kernels == nil {
		return nil, errors.New("xraykern: a kernel resolver is required")
	}
	if o.Runner == nil {
		o.Runner = ExecRunner{}
	}
	if o.StatusTimeout <= 0 {
		o.StatusTimeout = DefaultStatusTimeout
	}
	if o.ReloadTimeout <= 0 {
		o.ReloadTimeout = DefaultReloadTimeout
	}
	if o.PollInterval <= 0 {
		o.PollInterval = DefaultPollInterval
	}
	return &Client{opts: o}, nil
}

// Status reads the kernel's status document. A kernel that is not running
// answers with a connection error (the caller decides whether that means
// "stopped" or "not installed").
func (c *Client) Status(ctx context.Context) (xrayapi.Status, error) {
	var st xrayapi.Status
	client, url, err := statusEndpoint(c.opts.ConfigPath)
	if err != nil {
		return st, err
	}
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(ctx, c.opts.StatusTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return st, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return st, fmt.Errorf("读取 Xray 内核状态接口: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return st, fmt.Errorf("Xray 内核状态接口返回 HTTP %d", resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxStatusBytes)).Decode(&st); err != nil {
		return st, fmt.Errorf("解析 Xray 内核状态接口响应: %w", err)
	}
	return st, nil
}

// CheckStaged runs the installed kernel's check-staged command on a staged
// file set and returns its JSON verdict. A non-zero exit code with a valid
// JSON body is a "not ok" result, not a transport error; a kernel that is not
// installed is reported as ErrNotInstalled.
func (c *Client) CheckStaged(ctx context.Context, dir string, files []string) (xrayapi.StagedResult, error) {
	var res xrayapi.StagedResult
	if dir == "" || len(files) == 0 {
		return res, errors.New("xraykern: a staging directory and at least one file are required")
	}
	bin, err := c.kernelBinary()
	if err != nil {
		return res, err
	}
	args := []string{
		"check-staged",
		"-c", c.opts.ConfigPath,
		"--dir", dir,
		"--files", strings.Join(files, ","),
	}
	out, runErr := c.opts.Runner.Run(ctx, bin, args...)
	if err := json.Unmarshal(trimOutput(out), &res); err != nil {
		if runErr != nil {
			return res, fmt.Errorf("执行 %s check-staged: %w: %s", bin, runErr, oneLine(out))
		}
		return res, fmt.Errorf("解析 %s check-staged 的输出: %w: %s", bin, err, oneLine(out))
	}
	return res, nil
}

// WaitReloaded waits until the kernel reports fingerprint as its loaded
// configuration fingerprint, or until the reload timeout (default 30s) or ctx
// ends. It is the reloader the managed-file layer uses: a timeout makes the
// apply fail and the previous files are restored.
func (c *Client) WaitReloaded(ctx context.Context, fingerprint string) error {
	if fingerprint == "" {
		return errors.New("xraykern: an empty fingerprint cannot be waited for")
	}
	ctx, cancel := context.WithTimeout(ctx, c.opts.ReloadTimeout)
	defer cancel()
	var last error
	for {
		st, err := c.Status(ctx)
		switch {
		case err == nil && st.ConfigFingerprint == fingerprint:
			return nil
		case err != nil:
			last = err
		default:
			last = fmt.Errorf("内核报告的配置指纹是 %s", st.ConfigFingerprint)
		}
		t := time.NewTimer(c.opts.PollInterval)
		select {
		case <-ctx.Done():
			t.Stop()
			return fmt.Errorf("等待 Xray 内核重载配置超时（%s）: %v", c.opts.ReloadTimeout, last)
		case <-t.C:
		}
	}
}

// kernelBinary returns the absolute path of the installed current kernel
// binary, or ErrNotInstalled.
func (c *Client) kernelBinary() (string, error) {
	inst, err := c.opts.Kernels.Current(xrayapi.KernelName)
	if err != nil || inst.Path == "" {
		return "", ErrNotInstalled
	}
	return inst.Path, nil
}

// trimOutput strips the whitespace around a command's output so a trailing
// newline cannot break JSON decoding.
func trimOutput(b []byte) []byte { return []byte(strings.TrimSpace(string(b))) }

// oneLine collapses a command's output to one short line for an error message.
func oneLine(b []byte) string {
	s := strings.Join(strings.Fields(string(b)), " ")
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}
