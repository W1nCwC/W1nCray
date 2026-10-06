//go:build unix

package fileops

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// runtimeIsWindows is false here; it exists so path.go compiles on both
// platforms with one comparison rule.
const runtimeIsWindows = false

// openNoFollow opens p without following a final symlink. O_NOFOLLOW makes the
// kernel refuse a symlink instead of resolving it, which closes the window
// between the Lstat check and the open. O_NONBLOCK keeps a FIFO from blocking
// the open forever: a FIFO with no writer would otherwise hang the agent.
func openNoFollow(p string, dir bool) (*os.File, error) {
	flags := os.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
	if dir {
		flags |= syscall.O_DIRECTORY
	}
	return os.OpenFile(p, flags, 0)
}

// openRegular opens p for reading and refuses anything that is not a regular
// file, including a symlink and a FIFO.
func openRegular(p string) (*os.File, error) {
	f, err := openNoFollow(p, false)
	if err != nil {
		if isSymlinkErr(err) {
			return nil, wrapSymlink(p)
		}
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		_ = f.Close()
		return nil, notRegular(p)
	}
	return f, nil
}

// isSymlinkErr reports whether an open failed because the path is a symlink
// (ELOOP on Unix).
func isSymlinkErr(err error) bool {
	return errors.Is(err, syscall.ELOOP)
}

// wrapSymlink and notRegular keep the error text of the Unix and the Windows
// implementation identical, so a test asserts on the same sentinel either way.
func wrapSymlink(p string) error { return fmt.Errorf("%w: %s", ErrSymlink, p) }

func notRegular(p string) error { return fmt.Errorf("%w: %s", ErrNotRegular, p) }
