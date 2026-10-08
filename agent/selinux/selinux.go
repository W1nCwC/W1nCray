// Package selinux keeps the kernel binaries of an SELinux machine executable by
// the init system that starts them.
//
// The problem it solves (measured on CentOS Stream 9, targeted policy,
// enforcing): a kernel installed under the agent's state directory has the
// type etc_t, because that is what /etc gets. When systemd (init_t) starts a
// service whose ExecStart has type etc_t, the process does not transition to
// unconfined_service_t the way a binary under /usr/local (usr_t) does: it stays
// init_t. init_t is not allowed to create the kernel's status socket in
// /etc/W1nCray (etc_t), so the kernel dies at start-up with
//
//	avc: denied { create } for pid=... comm="W1nCray-xray" name="xray.sock"
//	  scontext=system_u:system_r:init_t:s0
//	  tcontext=system_u:object_r:etc_t:s0 tclass=sock_file
//
// Labelling the kernel tree bin_t makes systemd start it in
// unconfined_service_t — the same domain the agent itself runs in, since its
// binary lives under /usr/local — and the kernel can then bind its socket and
// its forwarding ports.
//
// The label is made persistent when semanage is available (one fcontext rule
// for the kernel tree plus restorecon) and falls back to chcon when it is not;
// a machine with neither tool is left untouched with a warning, because a
// missing tool must never turn into a failed installation. Nothing here runs at
// all when SELinux is off, so the package is a no-op on every other platform.
package selinux

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/W1nCwC/W1nCray/agent/driver"
)

// BinType is the SELinux type that makes the init system run a kernel binary in
// unconfined_service_t instead of init_t.
const BinType = "bin_t"

// SELinux modes as reported by Env.SELinux. "" means SELinux is disabled or
// absent.
const (
	ModeEnforcing  = "enforcing"
	ModePermissive = "permissive"
)

// enforcePath is the kernel interface that reports the current SELinux mode.
const enforcePath = "/sys/fs/selinux/enforce"

// Env is the machine surface the labeler needs. It is an interface so the unit
// tests can assert the exact command sequence of every path without a real
// SELinux machine.
type Env interface {
	// SELinux reports "enforcing", "permissive" or "" (disabled/absent).
	SELinux() string
	// LookPath resolves an executable, or "" when it is not installed.
	LookPath(file string) string
	// Run executes one command and returns its combined output.
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// OSEnv is the production Env.
type OSEnv struct{}

// SELinux implements Env.
func (OSEnv) SELinux() string {
	b, err := os.ReadFile(enforcePath)
	if err != nil {
		return ""
	}
	switch strings.TrimSpace(string(b)) {
	case "1":
		return ModeEnforcing
	case "0":
		return ModePermissive
	}
	return ""
}

// LookPath implements Env.
func (OSEnv) LookPath(file string) string {
	p, err := exec.LookPath(file)
	if err != nil {
		return ""
	}
	return p
}

// Run implements Env.
func (OSEnv) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	// name is a fixed SELinux tool (semanage, restorecon, chcon) and args is an
	// argv array holding paths this program computed, never a command string.
	return exec.CommandContext(ctx, name, args...).CombinedOutput() //nolint:noshell -- fixed SELinux tools
}

// Options configures a Labeler.
type Options struct {
	// Env is the machine surface (default OSEnv).
	Env Env
	// Log receives the labeler's events.
	Log driver.Logger
}

// Labeler applies the bin_t label to kernel binaries and trees.
type Labeler struct {
	env Env
	log driver.Logger

	mu sync.Mutex
	// trees are the directories labelled as a whole (one persistent fcontext
	// rule covers everything under them), files the individual binaries.
	trees map[string]bool
	files map[string]bool
}

// New builds a Labeler.
func New(o Options) *Labeler {
	if o.Env == nil {
		o.Env = OSEnv{}
	}
	var log driver.Logger = nopLog{}
	if o.Log != nil {
		log = o.Log
	}
	return &Labeler{env: o.Env, log: log, trees: map[string]bool{}, files: map[string]bool{}}
}

// Enabled reports whether SELinux is on. A machine with SELinux off needs no
// labelling and no tool.
func (l *Labeler) Enabled() bool { return l != nil && l.env.SELinux() != "" }

// EnsureBinT makes path — a kernel binary or a whole kernel tree — bin_t. It is
// idempotent: a path labelled once in this process is not labelled again, and a
// binary inside an already labelled tree is skipped, so one fcontext rule for
// the kernel tree is enough and per-version rules do not pile up.
//
// It never fails because a tool is missing (that would turn an SELinux
// misconfiguration into a failed installation); it only returns an error when a
// tool that is present refuses to do its job.
func (l *Labeler) EnsureBinT(ctx context.Context, path string) error {
	if l == nil || path == "" {
		return nil
	}
	mode := l.env.SELinux()
	if mode == "" {
		return nil // SELinux is off: the label cannot matter.
	}
	if l.marked(path) {
		return nil
	}
	if p := l.env.LookPath("semanage"); p != "" {
		if err := l.persistent(ctx, p, path); err == nil {
			l.mark(path)
			l.log.Infof("selinux: %s 已持久标记为 %s", path, BinType)
			return nil
		} else {
			l.log.Warnf("selinux: 持久标签失败，改用 chcon: %v", err)
		}
	}
	if p := l.env.LookPath("chcon"); p != "" {
		args := []string{"-t", BinType, path}
		if isDir(path) {
			args = []string{"-R", "-t", BinType, path}
		}
		if out, err := l.env.Run(ctx, p, args...); err != nil {
			return fmt.Errorf("selinux: chcon %s: %w: %s", path, err, oneLine(out))
		}
		l.mark(path)
		l.log.Infof("selinux: %s 已标记为 %s（临时；下次全盘 relabel 后需要重新执行）", path, BinType)
		return nil
	}
	l.log.Warnf("selinux: SELinux 处于 %s，但 semanage 与 chcon 都不可用；%s 的标签未修改，内核服务可能被拒绝（请安装 policycoreutils 或 policycoreutils-python-utils）", mode, path)
	return nil
}

// persistent adds one fcontext rule for path and applies it with restorecon.
// The rule is what survives a full relabel and a reboot; restorecon is what
// applies it now.
func (l *Labeler) persistent(ctx context.Context, semanage, path string) error {
	pattern := fcontextPattern(path)
	if out, err := l.env.Run(ctx, semanage, "fcontext", "-a", "-t", BinType, pattern); err != nil {
		return fmt.Errorf("semanage fcontext -a -t %s %s: %w: %s", BinType, pattern, err, oneLine(out))
	}
	restorecon := l.env.LookPath("restorecon")
	if restorecon == "" {
		return fmt.Errorf("semanage 已安装但 restorecon 缺失")
	}
	args := []string{"-F"}
	if isDir(path) {
		args = append(args, "-R")
	}
	args = append(args, path)
	if out, err := l.env.Run(ctx, restorecon, args...); err != nil {
		return fmt.Errorf("restorecon %s: %w: %s", path, err, oneLine(out))
	}
	return nil
}

// fcontextPattern is the semanage file-context pattern of path: the whole
// subtree for a directory, the exact path for a file. semanage matches the
// pattern as a regular expression, which is why a directory needs "(/.*)?" to
// cover everything under it.
func fcontextPattern(path string) string {
	if isDir(path) {
		return strings.TrimRight(path, "/") + "(/.*)?"
	}
	return path
}

// isDir reports whether path is an existing directory. A path that does not
// exist yet is treated as a file: chcon without -R still applies to it once it
// exists, and the caller relabels after every install anyway.
func isDir(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

// marked reports whether path is already covered: either it was labelled
// itself, or a directory tree containing it was labelled as a whole.
func (l *Labeler) marked(path string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.files[path] {
		return true
	}
	for d := range l.trees {
		if path == d || strings.HasPrefix(path, d+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func (l *Labeler) mark(path string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if isDir(path) {
		l.trees[path] = true
		return
	}
	l.files[path] = true
}

// oneLine collapses a command's output to one short line for an error message.
func oneLine(b []byte) string {
	s := strings.Join(strings.Fields(string(b)), " ")
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

type nopLog struct{}

func (nopLog) Debugf(string, ...any) {}
func (nopLog) Infof(string, ...any)  {}
func (nopLog) Warnf(string, ...any)  {}
func (nopLog) Errorf(string, ...any) {}
