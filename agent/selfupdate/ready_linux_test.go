//go:build linux

package selfupdate

import (
	"os"
	"path/filepath"
	"testing"
)

// TestUnitMentionsReadsTheInstallerUnits keeps the "a service manager runs
// exactly this executable" gate honest across the three backends install.sh
// writes (systemd, OpenRC, procd).
func TestUnitMentionsReadsTheInstallerUnits(t *testing.T) {
	exe := "/usr/local/bin/W1nCray"
	cases := []struct {
		name string
		text string
		want bool
	}{
		{
			name: "systemd",
			text: "[Service]\nExecStart=/usr/local/bin/W1nCray -c /etc/W1nCray/config.yml\nRestart=always\n",
			want: true,
		},
		{
			name: "openrc",
			text: "#!/sbin/openrc-run\nsupervisor=\"supervise-daemon\"\ncommand=\"/usr/local/bin/W1nCray\"\ncommand_args=\"-c /etc/W1nCray/config.yml\"\n",
			want: true,
		},
		{
			name: "procd",
			text: "USE_PROCD=1\nstart_service() {\n\tprocd_set_param command \"/usr/local/bin/W1nCray\" -c \"/etc/W1nCray/config.yml\"\n}\n",
			want: true,
		},
		{
			name: "another program",
			text: "ExecStart=/usr/bin/other -c /etc/other.yml\n",
			want: false,
		},
		{
			name: "commented out",
			text: "# ExecStart=/usr/local/bin/W1nCray -c /etc/W1nCray/config.yml\n",
			want: false,
		},
		{
			name: "mentioned but not started",
			text: "Description=W1nCray\nExecStart=/usr/bin/other\n",
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := unitMentions(tc.text, exe); got != tc.want {
				t.Errorf("unitMentions(%q) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

// TestWritableDirReportsTheRealAnswer covers the second half of Ready.
func TestWritableDirReportsTheRealAnswer(t *testing.T) {
	if err := writableDir(t.TempDir()); err != nil {
		t.Errorf("a temp dir must be writable: %v", err)
	}
	if err := writableDir(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("a missing directory must not be reported writable")
	}
}

// TestServiceUnitForNamesTheUnitToRestart covers the rollback half of the
// systemd integration: after a rollback the watchdog restarts exactly the unit
// that runs the executable, by the name systemctl knows it under.
func TestServiceUnitForNamesTheUnitToRestart(t *testing.T) {
	dir := t.TempDir()
	unit := filepath.Join(dir, "W1nCray.service")
	body := "[Service]\nExecStart=/usr/local/bin/W1nCray -c /etc/W1nCray/config.yml\nRestart=always\n"
	if err := os.WriteFile(unit, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	old := serviceUnits
	serviceUnits = []string{unit}
	t.Cleanup(func() { serviceUnits = old })

	if got := serviceUnitFor("/usr/local/bin/W1nCray"); got != "W1nCray.service" {
		t.Errorf("serviceUnitFor = %q, want W1nCray.service", got)
	}
	if got := serviceUnitFor("/usr/bin/other"); got != "" {
		t.Errorf("serviceUnitFor(other) = %q, want empty", got)
	}
	if got := serviceUnitFor(""); got != "" {
		t.Errorf("serviceUnitFor(\"\") = %q, want empty", got)
	}

	// An OpenRC init file runs the executable but is not a systemd unit: the
	// watchdog must not try "systemctl restart" there.
	openrc := filepath.Join(dir, "W1nCray")
	body = "#!/sbin/openrc-run\ncommand=\"/usr/local/bin/W1nCray\"\n"
	if err := os.WriteFile(openrc, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	serviceUnits = []string{openrc}
	if got := serviceUnitFor("/usr/local/bin/W1nCray"); got != "" {
		t.Errorf("serviceUnitFor(openrc) = %q, want empty", got)
	}
	if !unitRuns("/usr/local/bin/W1nCray") {
		t.Error("unitRuns must still accept an OpenRC init file")
	}
}

// TestReadyNeedsAServiceUnit proves the gate refuses a binary that no init file
// runs, which is what keeps the upgrade capability honest on a development box.
func TestReadyNeedsAServiceUnit(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "W1nCray")
	if err := os.WriteFile(exe, []byte("bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Ready(exe); err == nil {
		t.Error("a binary in a temp directory is run by no service unit and must not be self-updatable")
	}
	if err := Ready(filepath.Join(dir, "missing")); err == nil {
		t.Error("a missing executable must be refused")
	}
	if err := Ready(""); err == nil {
		t.Error("an empty path must be refused")
	}
}

// TestReadyAcceptsADeletedRunningImage is the D-M7 capability regression test.
// A rollback that races the new process's start unlinks the running image, so
// os.Executable() reports "<path> (deleted)". Ready must still accept the
// installed file (and the diagnostic must be readable) instead of withdrawing
// the upgrade capability for the life of the process. It failed before the fix.
func TestReadyAcceptsADeletedRunningImage(t *testing.T) {
	dir := t.TempDir()
	install := filepath.Join(dir, "W1nCray")
	if err := os.WriteFile(install, []byte("OLD-BINARY"), 0o755); err != nil {
		t.Fatal(err)
	}
	unit := filepath.Join(dir, "W1nCray.service")
	body := "[Service]\nExecStart=" + install + " -c /etc/W1nCray/config.yml\nRestart=always\n"
	if err := os.WriteFile(unit, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	old := serviceUnits
	serviceUnits = []string{unit}
	t.Cleanup(func() { serviceUnits = old })

	if err := Ready(install + deletedSuffix); err != nil {
		t.Fatalf("Ready(%q) = %v, want the installed path accepted", install+deletedSuffix, err)
	}
	if got := ServiceExecutable(); got != install {
		t.Errorf("ServiceExecutable = %q, want %q", got, install)
	}
}

// TestServiceExecutableReadsTheInstallerUnits covers the D-M7 fallback target
// across the three backends install.sh writes: the executable token (not the
// config file next to it) is the install path the swap has to target.
func TestServiceExecutableReadsTheInstallerUnits(t *testing.T) {
	dir := t.TempDir()
	install := filepath.Join(dir, "W1nCray")
	if err := os.WriteFile(install, []byte("bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(config, []byte("Log: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		text string
	}{
		{"systemd", "[Service]\nExecStart=" + install + " -c " + config + "\n"},
		{"openrc", "#!/sbin/openrc-run\ncommand=\"" + install + "\"\ncommand_args=\"-c " + config + "\"\n"},
		{"procd", "USE_PROCD=1\nstart_service() {\n\tprocd_set_param command \"" + install + "\" run -c \"" + config + "\"\n}\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := commandExecutable(tc.text); got != install {
				t.Errorf("commandExecutable = %q, want %q (the executable, never the config file)", got, install)
			}
		})
	}
	// A unit that starts another program yields nothing, and neither does one
	// whose command is commented out.
	if got := commandExecutable("ExecStart=/usr/bin/other\n"); got != "" {
		t.Errorf("commandExecutable(other) = %q, want empty", got)
	}
	if got := commandExecutable("# ExecStart=" + install + "\n"); got != "" {
		t.Errorf("commandExecutable(commented) = %q, want empty", got)
	}
}
