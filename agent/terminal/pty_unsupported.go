//go:build !(unix && (amd64 || 386 || arm || arm64 || mips || mipsle || mips64 || mips64le || ppc64 || ppc64le || riscv64 || s390x || loong64))

package terminal

// Supported is false on every platform without a PTY implementation: the
// manager stays inert and the agent never declares the terminal capability
// (design section 6.8, WP-G6 acceptance 3).
func Supported() bool { return false }

// ptyProcess is declared identically in both platform files so terminal.go
// compiles everywhere; on this platform nothing ever satisfies it.
type ptyProcess interface {
	read(p []byte) (int, error)
	write(p []byte) (int, error)
	resize(cols, rows uint16) error
	pid() int
	signalTerm() error
	signalKill() error
	wait() error
	close() error
}

// startPTY always fails here: a caller that ignored Supported() gets a clear
// error instead of a nil process.
func startPTY(shell string, env []string, cols, rows uint16) (ptyProcess, error) {
	return nil, ErrNoPTY
}
