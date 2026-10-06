package agentcfg

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/node"
)

// writeFile writes a file and fails the test on error.
func writeFile(t *testing.T, path, body string) string {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// configPath returns the config.yml path of a fresh directory, plus that
// directory.
func configPath(t *testing.T) (dir, path string) {
	t.Helper()
	dir = t.TempDir()
	return dir, filepath.Join(dir, "config.yml")
}

func TestLoadMissingFileIsNotAnError(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), FileName))
	if err != nil || cfg != nil {
		t.Fatalf("Load(missing) = %v, %v; want nil, nil", cfg, err)
	}
}

func TestLoadBrokenFileIsAnError(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, filepath.Join(dir, FileName), "Panel: [\n")
	_, err := Load(path)
	if err == nil {
		t.Fatal("Load accepted an unparsable agent.yml")
	}
	if !strings.Contains(err.Error(), FileName) {
		t.Errorf("the error does not name the file: %v", err)
	}
}

func TestLoadParsesTheAgentFields(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, filepath.Join(dir, FileName), `Enabled: true
StateDir: state
Panel:
  Enabled: true
  URL: https://panel.example.com
  MachineID: 7
  TokenFile: panel.token
Terminal:
  Enabled: true
  MaxSessions: 1
Files:
  Unrestricted: true
  AllowExec: true
Modules:
  XrayNodes: false
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg == nil || !cfg.Enabled || cfg.StateDir != "state" {
		t.Fatalf("cfg = %+v", cfg)
	}
	if cfg.Panel == nil || cfg.Panel.MachineID != 7 || cfg.Panel.TokenFile != "panel.token" {
		t.Fatalf("panel = %+v", cfg.Panel)
	}
	if !cfg.TerminalEnabled() || cfg.Terminal.Sessions() != 1 {
		t.Errorf("terminal = %+v", cfg.Terminal)
	}
	if cfg.Files == nil || !cfg.Files.Unrestricted || !cfg.Files.AllowExec {
		t.Errorf("files = %+v", cfg.Files)
	}
	if cfg.XrayNodesEnabled() {
		t.Error("Modules.XrayNodes: false must switch the node controllers off")
	}
}

func TestResolvePrecedence(t *testing.T) {
	t.Run("agent.yml wins as a whole", func(t *testing.T) {
		dir, path := configPath(t)
		fromConfig := &Config{Enabled: true, StateDir: "from-config", Panel: &PanelConfig{Enabled: true, MachineID: 1, URL: "https://p.example.com", Token: "t"}}
		writeFile(t, filepath.Join(dir, FileName), "Enabled: true\nStateDir: from-agentyml\n")
		cfg, src, base, err := Resolve(path, fromConfig)
		if err != nil {
			t.Fatal(err)
		}
		if src != SourceAgentYML || base != dir {
			t.Fatalf("src = %q, base = %q; want %q, %q", src, base, SourceAgentYML, dir)
		}
		if cfg.StateDir != "from-agentyml" {
			t.Errorf("StateDir = %q", cfg.StateDir)
		}
		// Never field-merged: the config.yml Panel is gone.
		if cfg.Panel != nil {
			t.Errorf("the agent.yml section was merged with config.yml: %+v", cfg.Panel)
		}
	})
	t.Run("without agent.yml the config block wins", func(t *testing.T) {
		dir, path := configPath(t)
		fromConfig := &Config{Enabled: true, StateDir: "from-config"}
		cfg, src, base, err := Resolve(path, fromConfig)
		if err != nil {
			t.Fatal(err)
		}
		if src != SourceConfig || cfg != fromConfig || base != dir {
			t.Fatalf("cfg = %+v, src = %q, base = %q", cfg, src, base)
		}
	})
	t.Run("neither", func(t *testing.T) {
		_, path := configPath(t)
		cfg, src, _, err := Resolve(path, nil)
		if err != nil || cfg != nil || src != SourceNone {
			t.Fatalf("cfg = %v, src = %q, err = %v", cfg, src, err)
		}
	})
	t.Run("a broken agent.yml is an error, never a fallback", func(t *testing.T) {
		dir, path := configPath(t)
		writeFile(t, filepath.Join(dir, FileName), "Enabled: [\n")
		cfg, src, _, err := Resolve(path, &Config{Enabled: true})
		if err == nil {
			t.Fatal("a broken agent.yml fell back to config.yml")
		}
		if cfg != nil || src != SourceNone {
			t.Errorf("cfg = %v, src = %q", cfg, src)
		}
	})
}

func TestWarnIfShadowed(t *testing.T) {
	dir, path := configPath(t)
	// No agent.yml: nothing is shadowed.
	if shadowed, agentPath := WarnIfShadowed(path, &Config{Enabled: true}); shadowed || agentPath != "" {
		t.Fatalf("shadowed = %v, path = %q", shadowed, agentPath)
	}
	// agent.yml without a config.yml Agent block: nothing is shadowed.
	writeFile(t, filepath.Join(dir, FileName), "Enabled: true\n")
	if shadowed, _ := WarnIfShadowed(path, nil); shadowed {
		t.Fatal("nothing to shadow without a config.yml Agent block")
	}
	// Both: the agent.yml path is reported.
	shadowed, agentPath := WarnIfShadowed(path, &Config{Enabled: true})
	if !shadowed || agentPath != filepath.Join(dir, FileName) {
		t.Fatalf("shadowed = %v, path = %q", shadowed, agentPath)
	}
}

// resolveLocal mimics what panel.LoadConfig does after validate(): defaults and
// exclusions resolved against the file that won.
func resolveLocal(t *testing.T, cfg *Config, configPath string) *Config {
	t.Helper()
	if cfg.StateDir == "" {
		cfg.StateDir = filepath.Join(filepath.Dir(configPath), "state")
	}
	if err := cfg.ResolveLocalPolicy(filepath.Dir(configPath), filepath.Dir(configPath), ExcludedPaths(configPath, cfg.StateDir)); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestLocalPolicyDefaults(t *testing.T) {
	dir, path := configPath(t)
	cfg := resolveLocal(t, &Config{Enabled: true}, path)

	if !cfg.TerminalEnabled() {
		t.Error("the terminal must default to ON (owner's decision)")
	}
	if cfg.Files == nil {
		t.Fatal("Files must be materialised")
	}
	want := []string{dir, filepath.Join(dir, "state")}
	if len(cfg.Files.Roots) != len(want) || cfg.Files.Roots[0] != want[0] || cfg.Files.Roots[1] != want[1] {
		t.Errorf("Roots = %v, want %v", cfg.Files.Roots, want)
	}
	if cfg.Files.Unrestricted || cfg.Files.AllowExec {
		t.Errorf("the file gates must default to closed: %+v", cfg.Files)
	}
	if !cfg.XrayNodesEnabled() {
		t.Error("Modules.XrayNodes must default to on")
	}
	if cfg.Dir() != dir {
		t.Errorf("Dir() = %q, want %q", cfg.Dir(), dir)
	}
	// The agent's own files are excluded, and none of them is a root.
	excluded := cfg.ExcludedFiles()
	wantExcluded := []string{filepath.Join(dir, FileName), filepath.Join(dir, "state", StateFileDesired), filepath.Join(dir, "state", StateFileLastGood)}
	if len(excluded) != len(wantExcluded) {
		t.Fatalf("ExcludedFiles() = %v, want %v", excluded, wantExcluded)
	}
	for i := range wantExcluded {
		if excluded[i] != wantExcluded[i] {
			t.Errorf("ExcludedFiles()[%d] = %q, want %q", i, excluded[i], wantExcluded[i])
		}
	}
	for _, root := range cfg.Files.Roots {
		for _, ex := range excluded {
			if root == ex {
				t.Errorf("root %q is an excluded file", root)
			}
		}
	}
}

func TestLocalPolicyRelativeRootsUseTheWinningDirectory(t *testing.T) {
	base := t.TempDir()
	sub := filepath.Join(base, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{Enabled: true, StateDir: "state", Files: &FilesConfig{Roots: []string{"xray", "logs"}}}
	if err := cfg.ResolveLocalPolicy(sub, sub, nil); err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{filepath.Join(sub, "xray"), filepath.Join(sub, "logs")} {
		if cfg.Files.Roots[i] != want {
			t.Errorf("Roots[%d] = %q, want %q", i, cfg.Files.Roots[i], want)
		}
	}
}

func TestLocalPolicyRefusesTheAgentsOwnFilesAsRoots(t *testing.T) {
	dir, path := configPath(t)
	excluded := ExcludedPaths(path, filepath.Join(dir, "state"))
	for _, tc := range []struct {
		name string
		root string
	}{
		{"agent.yml", filepath.Join(dir, FileName)},
		{"desired.json", filepath.Join(dir, "state", StateFileDesired)},
		{"last_good.json", filepath.Join(dir, "state", StateFileLastGood)},
		{"below agent.yml", filepath.Join(dir, FileName, "inner")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{Enabled: true, StateDir: filepath.Join(dir, "state"), Files: &FilesConfig{Roots: []string{tc.root}}}
			if err := cfg.ResolveLocalPolicy(dir, dir, excluded); err == nil {
				t.Fatalf("root %q was accepted", tc.root)
			} else if !strings.Contains(err.Error(), "never managed") {
				t.Errorf("err = %v", err)
			}
		})
	}
	// A root that merely contains agent.yml (the xray directory) is fine.
	cfg := &Config{Enabled: true, StateDir: filepath.Join(dir, "state")}
	if err := cfg.ResolveLocalPolicy(dir, dir, excluded); err != nil {
		t.Fatalf("the xray config directory must be a valid root: %v", err)
	}
}

func TestTerminalValidation(t *testing.T) {
	cases := []struct {
		name string
		tc   TerminalConfig
		want string
	}{
		{"defaults", TerminalConfig{}, ""},
		{"enabled", TerminalConfig{Enabled: boolPtr(true)}, ""},
		{"the cap", TerminalConfig{MaxSessions: MaxTerminalSessions}, ""},
		{"above the cap", TerminalConfig{MaxSessions: MaxTerminalSessions + 1}, "MaxSessions"},
		{"negative sessions", TerminalConfig{MaxSessions: -1}, "MaxSessions"},
		{"negative idle", TerminalConfig{IdleTimeoutS: -1}, "IdleTimeoutS"},
		{"negative duration", TerminalConfig{MaxDurationS: -1}, "MaxDurationS"},
		{"idle beyond the hard limit", TerminalConfig{IdleTimeoutS: 600, MaxDurationS: 300}, "must not exceed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.tc.Validate()
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.want != "" && err == nil:
				t.Fatal("accepted")
			case tc.want != "" && !strings.Contains(err.Error(), tc.want):
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
	if (*TerminalConfig)(nil).Validate() != nil {
		t.Error("a nil section must validate")
	}
}

func TestTerminalDefaults(t *testing.T) {
	var nilCfg *TerminalConfig
	if nilCfg.Sessions() != DefaultTerminalSessions || nilCfg.IdleTimeout() != DefaultTerminalIdleSeconds*time.Second || nilCfg.MaxDuration() != DefaultTerminalMaxDurationS*time.Second {
		t.Errorf("nil defaults = %d, %v, %v", nilCfg.Sessions(), nilCfg.IdleTimeout(), nilCfg.MaxDuration())
	}
	tc := &TerminalConfig{MaxSessions: 1, IdleTimeoutS: 60, MaxDurationS: 120}
	if tc.Sessions() != 1 || tc.IdleTimeout() != time.Minute || tc.MaxDuration() != 2*time.Minute {
		t.Errorf("set values = %d, %v, %v", tc.Sessions(), tc.IdleTimeout(), tc.MaxDuration())
	}
}

func TestValidateRequiresEnabledForThePanel(t *testing.T) {
	c := &Config{Enabled: false, Panel: &PanelConfig{Enabled: true}}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "requires Agent.Enabled") {
		t.Fatalf("err = %v", err)
	}
	if err := (*Config)(nil).Validate(); err != nil {
		t.Errorf("nil config: %v", err)
	}
}

func TestExcludedPaths(t *testing.T) {
	got := ExcludedPaths(filepath.Join("etc", "W1nCray", "config.yml"), filepath.Join("etc", "W1nCray", "state"))
	want := []string{
		filepath.Join("etc", "W1nCray", FileName),
		filepath.Join("etc", "W1nCray", "state", StateFileDesired),
		filepath.Join("etc", "W1nCray", "state", StateFileLastGood),
	}
	if len(got) != len(want) {
		t.Fatalf("ExcludedPaths() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("ExcludedPaths()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if only := ExcludedPaths("config.yml", ""); len(only) != 1 {
		t.Errorf("without a state directory: %v", only)
	}
}

func TestWriteFileIsAtomicAndKeepsABackup(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, filepath.Join(dir, FileName), "Enabled: false\n")

	backup, err := WriteFile(path, []byte("Enabled: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	if backup == "" {
		t.Fatal("the previous agent.yml was not backed up")
	}
	if got, err := os.ReadFile(backup); err != nil || string(got) != "Enabled: false\n" {
		t.Errorf("backup = %q, %v", got, err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "Enabled: true\n" {
		t.Errorf("agent.yml = %q, %v", got, err)
	}
	if cfg, err := Load(path); err != nil || cfg == nil || !cfg.Enabled {
		t.Errorf("the written file does not parse back: %+v, %v", cfg, err)
	}
	// No temporary file survives the swap.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("temporary file left behind: %s", e.Name())
		}
	}
	// A second write in the same second gets its own backup.
	backup2, err := WriteFile(path, []byte("Enabled: true\n# two\n"))
	if err != nil {
		t.Fatal(err)
	}
	if backup2 == backup || backup2 == "" {
		t.Fatalf("backups collide: %q / %q", backup, backup2)
	}
	if got, err := os.ReadFile(backup2); err != nil || string(got) != "Enabled: true\n" {
		t.Errorf("second backup = %q, %v", got, err)
	}
	// The first write of a new file has nothing to back up.
	other := filepath.Join(dir, "other.yml")
	if b, err := WriteFile(other, []byte("Enabled: true\n")); err != nil || b != "" {
		t.Errorf("first write backup = %q, %v", b, err)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Errorf("agent.yml mode = %04o, want 0600", perm)
		}
		fi, err = os.Stat(backup)
		if err != nil {
			t.Fatal(err)
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Errorf("backup mode = %04o, want 0600", perm)
		}
	}
}

func TestReadTokenFile(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, filepath.Join(dir, "panel.token"), "  tok-0123456789 \n")
	got, err := ReadTokenFile(path)
	if err != nil || got != "tok-0123456789" {
		t.Fatalf("ReadTokenFile = %q, %v", got, err)
	}
	// A missing file, an empty file and a file with more than a token fail.
	for name, body := range map[string]string{"empty": " \n", "two tokens": "a b\n"} {
		p := writeFile(t, filepath.Join(dir, name), body)
		if _, err := ReadTokenFile(p); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if _, err := ReadTokenFile(filepath.Join(dir, "missing")); err == nil {
		t.Error("a missing token file was accepted")
	}
	// The permission rule is a function of goos, so it is testable everywhere.
	if err := CheckTokenFileMode(path, 0o644, "linux"); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Errorf("loose mode: %v", err)
	}
	if err := CheckTokenFileMode(path, 0o600, "linux"); err != nil {
		t.Errorf("0600 refused: %v", err)
	}
	if err := CheckTokenFileMode(path, 0o644, "windows"); err != nil {
		t.Errorf("windows must skip the bit check: %v", err)
	}
}

func TestControllerConfigWithDefaults(t *testing.T) {
	cc := ControllerConfigWithDefaults(nil)
	if cc == nil || cc.ListenIP == "" {
		t.Fatalf("defaults = %+v", cc)
	}
	src := &node.Config{ListenIP: "127.0.0.1", UpdatePeriodic: 30}
	cc = ControllerConfigWithDefaults(src)
	if cc == src || cc.ListenIP != "127.0.0.1" || cc.UpdatePeriodic != 30 {
		t.Fatalf("override = %+v", cc)
	}
	if src.SendIP != "" {
		t.Errorf("the source was completed in place: %+v", src)
	}
}

func boolPtr(b bool) *bool { return &b }

// The terminal is on unless a machine explicitly opts out; a partial block must
// not switch it off by accident.
func TestTerminalEnabledSemantics(t *testing.T) {
	cases := []struct {
		name string
		cfg  *Config
		want bool
	}{
		{"nil config (no agent)", nil, false},
		{"nothing written", &Config{Enabled: true}, true},
		{"empty block", &Config{Enabled: true, Terminal: &TerminalConfig{}}, true},
		{"only limits written", &Config{Enabled: true, Terminal: &TerminalConfig{MaxSessions: 1}}, true},
		{"explicitly on", &Config{Enabled: true, Terminal: &TerminalConfig{Enabled: boolPtr(true)}}, true},
		{"explicitly off", &Config{Enabled: true, Terminal: &TerminalConfig{Enabled: boolPtr(false)}}, false},
	}
	for _, tc := range cases {
		if got := tc.cfg.TerminalEnabled(); got != tc.want {
			t.Errorf("%s: TerminalEnabled() = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestSeparatedLayout covers the managed-file gate of ruling 2: config.yml is
// only writable by the panel when the agent's own configuration lives in
// agent.yml. The rule is read from the file that won (SetSource) and, for
// callers that run before LoadConfig, from the file's presence.
func TestSeparatedLayout(t *testing.T) {
	dir, path := configPath(t)

	// No agent.yml: the config.yml block is the agent's own configuration.
	cfg := &Config{Enabled: true}
	cfg.SetSource(SourceConfig)
	if cfg.SeparatedLayout() {
		t.Error("SeparatedLayout = true with the config.yml block")
	}
	if Separated(path) {
		t.Error("Separated = true without an agent.yml")
	}
	if (&Config{}).SeparatedLayout() || ((*Config)(nil)).SeparatedLayout() {
		t.Error("the zero value must not claim the separated layout")
	}

	// agent.yml present: it wins as a whole, so config.yml only carries the
	// xray settings and may be managed.
	writeFile(t, filepath.Join(dir, FileName), "Enabled: true\nStateDir: state\n")
	cfg.SetSource(SourceAgentYML)
	if !cfg.SeparatedLayout() {
		t.Error("SeparatedLayout = false with agent.yml in charge")
	}
	if !Separated(path) {
		t.Error("Separated = false although agent.yml exists")
	}
}
