//go:build !unix

package selfupdate

import (
	"github.com/W1nCwC/W1nCray/agent/driver"
)

// Supported reports whether this build can replace its own executable and
// respawn it. On Windows a running executable cannot be renamed, so
// self_update is refused with ErrNotSupported instead of half-working.
func Supported() bool { return false }

// respawn is not possible on this platform.
func respawn(string, HelperOptions, driver.Logger) error { return ErrNotSupported }

// processAlive cannot be answered portably here; the watchdog never runs.
func processAlive(int) bool { return false }
