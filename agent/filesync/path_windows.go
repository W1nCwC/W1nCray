//go:build windows

package filesync

import (
	"errors"
	"io/fs"
	"os"
)

// renameOver renames src over dst on Windows, where os.Rename refuses to
// replace an existing file. Removing the destination first loses the atomic
// guarantee Windows does not offer for this operation anyway; the caller always
// keeps a last_good snapshot before it replaces anything.
func renameOver(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	if err := os.Remove(dst); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return os.Rename(src, dst)
}
