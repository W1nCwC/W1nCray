package selfupdate

import (
	"os"
	"runtime"
)

func isWindows() bool { return runtime.GOOS == "windows" }

// syncDir flushes a directory entry (the renames of Commit/Rollback) to disk
// where the OS allows it. Opening a directory for Sync is not supported on
// Windows; the error is ignored there.
func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Sync(); err != nil && !isWindows() {
		return err
	}
	return nil
}
