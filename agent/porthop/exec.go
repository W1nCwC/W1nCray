package porthop

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// Executor runs the external firewall tools. It is an interface so the unit
// tests can drive the Manager with a fake and no firewall.
type Executor interface {
	// Run executes name with args and returns its combined output.
	Run(ctx context.Context, name string, args ...string) (string, error)
	// RunWithStdinFile is Run with the contents of stdinFile on standard input
	// (the equivalent of "name args < stdinFile"); iptables-restore needs it.
	RunWithStdinFile(ctx context.Context, stdinFile, name string, args ...string) (string, error)
}

// SystemExecutor runs real commands. Binaries missing from PATH are also looked
// up in /usr/sbin and /sbin, which a service environment often omits.
type SystemExecutor struct{}

// allowedTools are the only programs the executor will start: the netfilter
// front ends, always with an argv array, never a shell string.
var allowedTools = map[string]bool{
	"nft": true, "iptables": true, "ip6tables": true,
	"iptables-restore": true, "ip6tables-restore": true,
}

func resolve(name string) string {
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	for _, d := range []string{"/usr/sbin", "/sbin"} {
		p := filepath.Join(d, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return name
}

// Run implements Executor.
func (SystemExecutor) Run(ctx context.Context, name string, args ...string) (string, error) {
	if !allowedTools[name] {
		return "", fmt.Errorf("porthop: %q is not a firewall tool", name)
	}
	out, err := exec.CommandContext(ctx, resolve(name), args...).CombinedOutput() //nolint:noshell -- fixed netfilter tool with an argv array
	return string(out), err
}

// RunWithStdinFile implements Executor.
func (SystemExecutor) RunWithStdinFile(ctx context.Context, stdinFile, name string, args ...string) (string, error) {
	if !allowedTools[name] {
		return "", fmt.Errorf("porthop: %q is not a firewall tool", name)
	}
	f, err := os.Open(stdinFile)
	if err != nil {
		return "", err
	}
	defer f.Close()
	cmd := exec.CommandContext(ctx, resolve(name), args...) //nolint:noshell -- fixed netfilter tool with an argv array
	cmd.Stdin = f
	out, err := cmd.CombinedOutput()
	return string(out), err
}
