//go:build !linux

package selfupdate

// Ready reports why this executable cannot self-update in place. Only Linux
// has the service managers (systemd, OpenRC, procd) this program installs
// itself into, so every other platform is refused.
func Ready(string) error { return ErrNotSupported }
