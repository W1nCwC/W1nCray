package agentcfg

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// maxBackupsPerSecond bounds the numeric suffix search so a broken clock or a
// directory full of backups can never spin here.
const maxBackupsPerSecond = 100

// WriteFile writes data to path atomically and keeps one backup of the file it
// replaces. agent.yml holds the machine token and can veto the service start
// (design R5), so it is created 0600 and swapped in by renaming a fully written
// temporary file in the same directory: a crash can never leave a half-written
// agent.yml behind. The backup path is returned ("" when there was no previous
// file).
func WriteFile(path string, data []byte) (backup string, err error) {
	switch _, statErr := os.Stat(path); {
	case statErr == nil:
		backup, err = backupFile(path)
		if err != nil {
			return "", err
		}
	case errors.Is(statErr, fs.ErrNotExist):
		// First write: nothing to back up.
	default:
		return "", fmt.Errorf("agent config %s: %w", path, statErr)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return backup, fmt.Errorf("write agent config %s: %w", path, err)
	}
	tmpName := tmp.Name()
	defer func() {
		if tmpName != "" {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return backup, fmt.Errorf("write agent config %s: %w", path, err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return backup, fmt.Errorf("write agent config %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return backup, fmt.Errorf("write agent config %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return backup, fmt.Errorf("write agent config %s: %w", path, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return backup, fmt.Errorf("replace agent config %s: %w", path, err)
	}
	tmpName = "" // renamed away: nothing left to clean up
	return backup, nil
}

// backupFile copies path to path + ".bak-<timestamp>" (0600) and returns the
// backup path. A second backup in the same second gets a numeric suffix, so an
// operator never loses the file they are about to replace.
func backupFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("backup agent config %s: %w", path, err)
	}
	ts := time.Now().Format("20060102-150405")
	for i := 0; i < maxBackupsPerSecond; i++ {
		candidate := path + ".bak-" + ts
		if i > 0 {
			candidate = fmt.Sprintf("%s.bak-%s-%d", path, ts, i+1)
		}
		switch _, err := os.Stat(candidate); {
		case errors.Is(err, fs.ErrNotExist):
			if err := os.WriteFile(candidate, data, 0o600); err != nil {
				return "", fmt.Errorf("backup agent config %s: %w", candidate, err)
			}
			// WriteFile applies the umask; the backup is a secret too.
			if err := os.Chmod(candidate, 0o600); err != nil {
				return "", fmt.Errorf("backup agent config %s: %w", candidate, err)
			}
			return candidate, nil
		case err != nil:
			return "", fmt.Errorf("backup agent config %s: %w", candidate, err)
		}
	}
	return "", fmt.Errorf("backup agent config %s: too many backups for %s", path, ts)
}
