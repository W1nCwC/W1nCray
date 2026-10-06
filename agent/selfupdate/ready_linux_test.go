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
