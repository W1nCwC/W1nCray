//go:build !windows

package filesync

import "os"

// renameOver renames src over dst. On Unix-like systems os.Rename already
// replaces the destination atomically, which is what makes a managed-file
// replacement crash-safe.
func renameOver(src, dst string) error { return os.Rename(src, dst) }
