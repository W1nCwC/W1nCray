package fileops

import "testing"

// A standard install keeps its config in /etc/W1nCray, which is the default
// file-ops root; v0.5.0 refused it and the agent failed to boot.
func TestSystemDirectoryRulesAllowAppSubdirectories(t *testing.T) {
	for _, ok := range []string{"/etc/W1nCray", "/etc/W1nCray/state", "/usr/local/W1nCray", "/var/lib/w1ncray"} {
		if err := checkRootIsSane(ok); err != nil {
			t.Errorf("%s refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"/", "/etc", "/usr", "/var", "/proc/1", "/sys/kernel", "/dev/shm", "/tmp"} {
		if err := checkRootIsSane(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}
