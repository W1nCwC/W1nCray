package agentcfg

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/selfupdate"
	"github.com/W1nCwC/W1nCray/nodecfg"
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
	if cfg.Files == nil || cfg.Files.Unrestricted == nil || !*cfg.Files.Unrestricted || !cfg.Files.AllowExec {
		t.Errorf("files = %+v", cfg.Files)
	}
	if cfg.XrayNodesEnabled() {
		t.Error("Modules.XrayNodes: false must switch the node controllers off")
	}
}

// TestKernelsAllowHTTPIsALocalSwitch covers D-M1: the agent.yml
// Kernels.AllowHTTP switch exists, defaults to false (https only) and is read
// from the machine's own configuration file. Nothing the panel pushes can set
// it — the panel sends a desired state, never agent configuration.
func TestKernelsAllowHTTPIsALocalSwitch(t *testing.T) {
	var nilCfg *Config
	if nilCfg.KernelsAllowHTTP() {
		t.Error("a nil Config must not permit http kernel sources")
	}
	if (&Config{}).KernelsAllowHTTP() {
		t.Error("a Config without a Kernels section must not permit http")
	}
	if (&Config{Kernels: &KernelsConfig{}}).KernelsAllowHTTP() {
		t.Error("Kernels.AllowHTTP must default to false")
	}
	if !(&Config{Kernels: &KernelsConfig{AllowHTTP: true}}).KernelsAllowHTTP() {
		t.Error("Kernels.AllowHTTP: true was ignored")
	}

	dir := t.TempDir()
	path := writeFile(t, filepath.Join(dir, FileName), "Enabled: true\nKernels:\n  AllowHTTP: true\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.KernelsAllowHTTP() {
		t.Errorf("agent.yml Kernels.AllowHTTP was not read: %+v", cfg.Kernels)
	}
	// The switch is a local gate, not a policy: validation accepts it and the
	// file that carries it stays loadable.
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}

	// The config.yml "Agent:" block uses the same field names, so a machine on
	// the old layout gets the switch too.
	block, err := Load(writeFile(t, filepath.Join(dir, "other.yml"), "Enabled: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	if block.KernelsAllowHTTP() {
		t.Error("a config without the section must stay https-only")
	}
}

// TestFrpReadyTimeoutIsAnOptionalLocalOverride covers D4's configuration half:
// Drivers.Frp.ReadyTimeoutSec overrides the frp driver's readiness limit, is
// absent by default (the architecture default applies) and refuses a negative
// value.
func TestFrpReadyTimeoutIsAnOptionalLocalOverride(t *testing.T) {
	var nilCfg *Config
	if d, ok := nilCfg.FrpReadyTimeout(); ok || d != 0 {
		t.Errorf("nil Config = (%s, %v), want (0, false)", d, ok)
	}
	if _, ok := (&Config{}).FrpReadyTimeout(); ok {
		t.Error("a Config without a Drivers section must use the driver default")
	}
	if _, ok := (&Config{Drivers: &DriversConfig{}}).FrpReadyTimeout(); ok {
		t.Error("a Drivers section without Frp must use the driver default")
	}
	if _, ok := (&Config{Drivers: &DriversConfig{Frp: &FrpConfig{}}}).FrpReadyTimeout(); ok {
		t.Error("ReadyTimeoutSec 0 must mean the driver default")
	}
	if d, ok := (&Config{Drivers: &DriversConfig{Frp: &FrpConfig{ReadyTimeoutSec: 90}}}).FrpReadyTimeout(); !ok || d != 90*time.Second {
		t.Errorf("explicit override = (%s, %v), want (1m30s, true)", d, ok)
	}

	// The field is read from agent.yml.
	dir := t.TempDir()
	path := writeFile(t, filepath.Join(dir, FileName), "Enabled: true\nDrivers:\n  Frp:\n    ReadyTimeoutSec: 45\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if d, ok := cfg.FrpReadyTimeout(); !ok || d != 45*time.Second {
		t.Errorf("agent.yml override = (%s, %v), want (45s, true)", d, ok)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}

	// A negative value is refused instead of silently ignored.
	bad := &Config{Enabled: true, Drivers: &DriversConfig{Frp: &FrpConfig{ReadyTimeoutSec: -1}}}
	if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "ReadyTimeoutSec") {
		t.Errorf("Validate(negative) = %v, want a ReadyTimeoutSec error", err)
	}
}

// TestGostReadyTimeoutIsAnOptionalLocalOverride covers F6's configuration half:
// Drivers.Gost.ReadyTimeoutSec mirrors the frp override, is absent by default
// (the shared driver default applies) and refuses a negative value.
func TestGostReadyTimeoutIsAnOptionalLocalOverride(t *testing.T) {
	var nilCfg *Config
	if d, ok := nilCfg.GostReadyTimeout(); ok || d != 0 {
		t.Errorf("nil Config = (%s, %v), want (0, false)", d, ok)
	}
	if _, ok := (&Config{}).GostReadyTimeout(); ok {
		t.Error("a Config without a Drivers section must use the driver default")
	}
	if _, ok := (&Config{Drivers: &DriversConfig{}}).GostReadyTimeout(); ok {
		t.Error("a Drivers section without Gost must use the driver default")
	}
	if _, ok := (&Config{Drivers: &DriversConfig{Gost: &GostConfig{}}}).GostReadyTimeout(); ok {
		t.Error("ReadyTimeoutSec 0 must mean the driver default")
	}
	if d, ok := (&Config{Drivers: &DriversConfig{Gost: &GostConfig{ReadyTimeoutSec: 45}}}).GostReadyTimeout(); !ok || d != 45*time.Second {
		t.Errorf("explicit override = (%s, %v), want (45s, true)", d, ok)
	}

	// Both drivers are read from the same agent.yml section, independently.
	dir := t.TempDir()
	path := writeFile(t, filepath.Join(dir, FileName), "Enabled: true\nDrivers:\n  Frp:\n    ReadyTimeoutSec: 45\n  Gost:\n    ReadyTimeoutSec: 90\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if d, ok := cfg.GostReadyTimeout(); !ok || d != 90*time.Second {
		t.Errorf("agent.yml gost override = (%s, %v), want (1m30s, true)", d, ok)
	}
	if d, ok := cfg.FrpReadyTimeout(); !ok || d != 45*time.Second {
		t.Errorf("agent.yml frp override = (%s, %v), want (45s, true)", d, ok)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}

	// A negative value is refused instead of silently ignored.
	bad := &Config{Enabled: true, Drivers: &DriversConfig{Gost: &GostConfig{ReadyTimeoutSec: -1}}}
	if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "Gost.ReadyTimeoutSec") {
		t.Errorf("Validate(negative) = %v, want a Gost.ReadyTimeoutSec error", err)
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
	if cfg.Files.AllowExec {
		t.Errorf("AllowExec must default to false: %+v", cfg.Files)
	}
	// The terminal defaults to ON, so the file manager follows it: PLAN v10's
	// three-state rule means "not written" is unrestricted on a machine whose
	// root shell is already reachable. An explicit false is what confines it.
	if !cfg.UnrestrictedEnabled() || cfg.Files.Unrestricted == nil || !*cfg.Files.Unrestricted {
		t.Errorf("Files.Unrestricted must follow the terminal default (on): %+v", cfg.Files)
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

// TestUnrestrictedTriState pins PLAN v10's three-state rule for
// Files.Unrestricted: an absent value follows the terminal gate, an explicit
// value wins, and ResolveLocalPolicy materialises the effective value so every
// consumer (the panel's fileops options, hello.policy.files) reads it.
func TestUnrestrictedTriState(t *testing.T) {
	cases := []struct {
		name          string
		terminal      *TerminalConfig
		unrestricted  *bool
		wantEffective bool
	}{
		{"unset + terminal on", nil, nil, true},
		{"unset + terminal off", &TerminalConfig{Enabled: boolPtr(false)}, nil, false},
		{"explicit true + terminal off", &TerminalConfig{Enabled: boolPtr(false)}, boolPtr(true), true},
		{"explicit false + terminal on", nil, boolPtr(false), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, path := configPath(t)
			cfg := resolveLocal(t, &Config{Enabled: true, Terminal: tc.terminal, Files: &FilesConfig{Unrestricted: tc.unrestricted}}, path)
			if got := cfg.UnrestrictedEnabled(); got != tc.wantEffective {
				t.Errorf("UnrestrictedEnabled() = %v, want %v", got, tc.wantEffective)
			}
			if cfg.Files.Unrestricted == nil || *cfg.Files.Unrestricted != tc.wantEffective {
				t.Errorf("materialised Unrestricted = %v, want %v", cfg.Files.Unrestricted, tc.wantEffective)
			}
		})
	}
	// An unresolved Config has no Files section at all: the accessor must stay
	// on the safe side (restricted) instead of inventing a policy.
	raw := &Config{Enabled: true}
	if raw.UnrestrictedEnabled() {
		t.Error("a Config without a Files section must not report unrestricted")
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
	src := &nodecfg.Config{ListenIP: "127.0.0.1", UpdatePeriodic: 30}
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

// TestLocalPolicyAlwaysHasTheXrayRootAndHidesTheToken (PLAN v10 WP-C): explicit
// Roots elsewhere still get the xray configuration directory added, a shallow
// one is not added, and the machine token file is excluded.
func TestLocalPolicyAlwaysHasTheXrayRootAndHidesTheToken(t *testing.T) {
	base := t.TempDir()
	xrayDir := filepath.Join(base, "etc", "W1nCray")
	other := filepath.Join(base, "files")
	cfg := &Config{Enabled: true, StateDir: filepath.Join(base, "state"),
		Files: &FilesConfig{Roots: []string{other}},
		Panel: &PanelConfig{TokenFile: filepath.Join(xrayDir, "agent.token")}}
	if err := cfg.ResolveLocalPolicy(xrayDir, xrayDir, nil); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Files.Roots) != 2 || cfg.Files.Roots[1] != xrayDir {
		t.Errorf("Roots = %v, want [%s %s]", cfg.Files.Roots, other, xrayDir)
	}
	found := false
	for _, e := range cfg.ExcludedFiles() {
		if e == filepath.Join(xrayDir, "agent.token") {
			found = true
		}
	}
	if !found {
		t.Errorf("the token file is not excluded: %v", cfg.ExcludedFiles())
	}

	shallow := &Config{Enabled: true, Files: &FilesConfig{Roots: []string{other}}}
	if err := shallow.ResolveLocalPolicy(base, string(filepath.Separator)+"etc", nil); err != nil {
		t.Fatal(err)
	}
	if len(shallow.Files.Roots) != 1 {
		t.Errorf("a shallow xray directory must not be added: %v", shallow.Files.Roots)
	}
}

// TestFirewallAutoOpenDefaults pins the three-state switch of PLAN v11 D2:
// "not written" follows the platform (on for OpenWrt, off elsewhere), an
// explicit value is honoured on OpenWrt, and a non-OpenWrt machine never turns
// it on because the agent has no firewall automation there.
func TestFirewallAutoOpenDefaults(t *testing.T) {
	on, off := true, false
	cases := []struct {
		name    string
		cfg     *Config
		openWrt bool
		want    bool
	}{
		{"nil config on openwrt", nil, true, true},
		{"nil config elsewhere", nil, false, false},
		{"not written on openwrt", &Config{}, true, true},
		{"not written elsewhere", &Config{}, false, false},
		{"explicit on", &Config{Firewall: &FirewallConfig{AutoOpen: &on}}, true, true},
		{"explicit off", &Config{Firewall: &FirewallConfig{AutoOpen: &off}}, true, false},
		{"explicit on elsewhere", &Config{Firewall: &FirewallConfig{AutoOpen: &on}}, false, false},
	}
	for _, c := range cases {
		if got := c.cfg.FirewallAutoOpen(c.openWrt); got != c.want {
			t.Errorf("%s: FirewallAutoOpen = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestSelfUpdateWindowsAreALocalArchitectureAwareOverride pins the D-M7 timing
// rule: the watchdog windows come from the architecture by default, a local
// agent.yml value overrides them, and a deadline that is not above the window is
// raised so the rollback rule can still fire.
func TestSelfUpdateWindowsAreALocalArchitectureAwareOverride(t *testing.T) {
	// Defaults: architecture-driven, never the old fixed 10 s.
	alive, deadline := (*Config)(nil).SelfUpdateWindows("amd64")
	if alive != selfupdate.DefaultAliveWindow || deadline != selfupdate.DefaultDeadline {
		t.Errorf("nil config on amd64 = %s/%s, want %s/%s", alive, deadline, selfupdate.DefaultAliveWindow, selfupdate.DefaultDeadline)
	}
	slowAlive, _ := (*Config)(nil).SelfUpdateWindows("mips")
	if slowAlive != selfupdate.DefaultAliveWindowSlow || slowAlive <= alive {
		t.Errorf("the slow-target window %s must be the slow default %s and exceed the amd64 one %s", slowAlive, selfupdate.DefaultAliveWindowSlow, alive)
	}

	cfg := &Config{SelfUpdate: &SelfUpdateConfig{AliveWindowSec: 90, DeadlineSec: 600}}
	alive, deadline = cfg.SelfUpdateWindows("mips")
	if alive != 90*time.Second || deadline != 600*time.Second {
		t.Errorf("override = %s/%s, want 90s/10m0s", alive, deadline)
	}

	// A deadline below the window is raised, not honoured: a watchdog that
	// stops watching before its rollback rule fires would leave a broken
	// binary in place.
	cfg = &Config{SelfUpdate: &SelfUpdateConfig{AliveWindowSec: 300, DeadlineSec: 60}}
	alive, deadline = cfg.SelfUpdateWindows("amd64")
	if alive != 300*time.Second || deadline <= alive {
		t.Errorf("misconfigured budget = %s/%s, want the deadline raised above 300s", alive, deadline)
	}

	// Zero and negative values mean "use the default", and a negative value is
	// refused by Validate.
	if a, d := (&Config{SelfUpdate: &SelfUpdateConfig{}}).SelfUpdateWindows("amd64"); a != selfupdate.DefaultAliveWindow || d != selfupdate.DefaultDeadline {
		t.Errorf("zero values = %s/%s, want the architecture defaults", a, d)
	}
	if err := (&Config{SelfUpdate: &SelfUpdateConfig{AliveWindowSec: -1}}).Validate(); err == nil {
		t.Error("a negative window must be refused")
	}
}
