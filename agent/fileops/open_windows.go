//go:build !unix

package fileops

import (
	"fmt"
	"os"
)

// runtimeIsWindows is true here; it exists so path.go compiles on both
// platforms with one comparison rule.
const runtimeIsWindows = true

// openNoFollow opens p. Windows has no O_NOFOLLOW, so the symlink refusal
// relies on the Lstat check the caller performs first; os.Open on a symlink
// resolves it, which is why Resolve refuses a link before this is reached.
func openNoFollow(p string, dir bool) (*os.File, error) {
	return os.Open(p)
}

// openRegular opens p and refuses anything that is not a regular file.
func openRegular(p string) (*os.File, error) {
	fi, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, wrapSymlink(p)
	}
	if !fi.Mode().IsRegular() {
		return nil, notRegular(p)
	}
	return os.Open(p)
}

// isSymlinkErr has no kernel-level equivalent on Windows: the check is the
// Lstat the caller already did.
func isSymlinkErr(error) bool { return false }

// wrapSymlink and notRegular keep the error text of the Unix and the Windows
// implementation identical, so a test asserts on the same sentinel either way.
func wrapSymlink(p string) error { return fmt.Errorf("%w: %s", ErrSymlink, p) }

func notRegular(p string) error { return fmt.Errorf("%w: %s", ErrNotRegular, p) }
