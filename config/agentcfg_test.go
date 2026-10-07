package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	log "github.com/sirupsen/logrus"

	"github.com/W1nCwC/W1nCray/agent/agentcfg"
)

// Split: the running-service cases that used to live in this file moved with
// the panel, which was split into config/xraynode/agentd:
//
//   - TestCheckReportNamesTheAgentYMLSource, and the CheckReport half of
//     TestBrokenAgentYMLStopsTheLoadAndIsReportedFirst, drove panel.CheckReport;
//     that report now lives in agentd (agentd/check.go), which owns the
//     running agent.
//   - TestAgentYMLHotReload and TestAgentYMLCreatedLaterIsPickedUp drove a
//     running panel.New(...).Start() watcher; the agentd worker (and xraynode
//     for the Xray side) recreates those.
//
// The cases kept below are the pure loader cases: they call Load and read the
// returned *Config, so they belong to this package.

// writeAgentYML writes an agent.yml with the given body.
func writeAgentYML(t *testing.T, dir, body string) string {
	t.Helper()
	path := filepath.Join(dir, agentcfg.FileName)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// writeAgentOnlyConfig writes a config.yml whose only agent configuration is
// the legacy "Agent:" block (no Nodes, no agent.yml).
func writeAgentOnlyConfig(t *testing.T, dir, stateDir string) string {
	t.Helper()
	path := filepath.Join(dir, "config.yml")
	body := fmt.Sprintf("Log: {Level: warning}\nAgent:\n  Enabled: true\n  StateDir: %s\n", stateDir)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// Split: the shared test log hook used by TestAgentYMLWinsOverTheConfigBlock
// was defined in panel/nodecontrollers_test.go, which now belongs to xraynode;
// the config package keeps its own copy so the warning assertion can stay here.
type logCapture struct {
	mu   sync.Mutex
	msgs []string
}

func (c *logCapture) Levels() []log.Level { return log.AllLevels }

func (c *logCapture) Fire(e *log.Entry) error {
	c.mu.Lock()
	c.msgs = append(c.msgs, e.Message)
	c.mu.Unlock()
	return nil
}

func (c *logCapture) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Join(c.msgs, "\n")
}

// captureLogs installs a log hook and restores the logger afterwards.
func captureLogs(t *testing.T) *logCapture {
	t.Helper()
	c := &logCapture{}
	oldHooks := log.StandardLogger().ReplaceHooks(make(log.LevelHooks))
	oldLevel := log.GetLevel()
	log.SetLevel(log.InfoLevel)
	log.AddHook(c)
	t.Cleanup(func() {
		log.StandardLogger().ReplaceHooks(oldHooks)
		log.SetLevel(oldLevel)
	})
	return c
}

// TestLoadRealV03FixtureStillLoads pins the compatibility promise: a real
// single-file config (the v0.3 fixture cmd/link_test.go uses) keeps loading
// byte for byte, with no agent configuration.
//
// Split: the full loader panel.LoadConfig is named Load in this package; the
// test keeps its coverage of the full (Nodes + agent) load.
func TestLoadRealV03FixtureStillLoads(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "cmd", "testdata", "link_v03_real.yml"))
	if err != nil {
		t.Fatalf("the v0.3 fixture no longer loads: %v", err)
	}
	if len(cfg.NodesConfig) != 3 {
		t.Errorf("%d static nodes, want 3", len(cfg.NodesConfig))
	}
	if cfg.Agent != nil {
		t.Errorf("the fixture has no Agent section, got %+v", cfg.Agent)
	}
	if cfg.AgentSource() != agentcfg.SourceNone || cfg.AgentSourcePath() != "" {
		t.Errorf("source = %q / %q, want none", cfg.AgentSource(), cfg.AgentSourcePath())
	}
}

// TestAgentYMLWinsOverTheConfigBlock is the D1 precedence: agent.yml is used as
// a whole, the config.yml Agent block is ignored and the operator is warned.
func TestAgentYMLWinsOverTheConfigBlock(t *testing.T) {
	dir := t.TempDir()
	configPath := writeAgentOnlyConfig(t, dir, "state-from-config")
	agentPath := writeAgentYML(t, dir, "Enabled: true\nStateDir: state-from-agentyml\n")

	cap := captureLogs(t)
	// Split: panel.LoadConfig -> config.Load (full load, validates Nodes).
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AgentSource() != agentcfg.SourceAgentYML {
		t.Errorf("source = %q, want %q", cfg.AgentSource(), agentcfg.SourceAgentYML)
	}
	if cfg.AgentSourcePath() != agentPath {
		t.Errorf("source path = %q, want %q", cfg.AgentSourcePath(), agentPath)
	}
	if want := filepath.Join(dir, "state-from-agentyml"); cfg.Agent.StateDir != want {
		t.Errorf("StateDir = %q, want %q", cfg.Agent.StateDir, want)
	}
	warn := cap.String()
	if !strings.Contains(warn, "wins over the Agent block") {
		t.Errorf("no warning was logged:\n%s", warn)
	}
	if !strings.Contains(warn, agentPath) || !strings.Contains(warn, configPath) {
		t.Errorf("the warning does not name both files:\n%s", warn)
	}
}

// TestAgentYMLPathsFollowItsOwnDirectory: the winning file's directory is the
// base for StateDir, KernelsDir and TokenFile, not the process working
// directory.
func TestAgentYMLPathsFollowItsOwnDirectory(t *testing.T) {
	base := t.TempDir()
	sub := filepath.Join(base, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := writeAgentOnlyConfig(t, sub, "state-from-config")
	writeAgentYML(t, sub, `Enabled: true
StateDir: state
Panel:
  Enabled: true
  URL: https://panel.example.com
  MachineID: 7
  TokenFile: panel.token
`)
	// Split: panel.LoadConfig -> config.Load.
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(sub, "state"); cfg.Agent.StateDir != want {
		t.Errorf("StateDir = %q, want %q", cfg.Agent.StateDir, want)
	}
	if want := filepath.Join(sub, "state", "kernels"); cfg.Agent.KernelsDir != want {
		t.Errorf("KernelsDir = %q, want %q", cfg.Agent.KernelsDir, want)
	}
	if want := filepath.Join(sub, "panel.token"); cfg.Agent.Panel.TokenFile != want {
		t.Errorf("TokenFile = %q, want %q", cfg.Agent.Panel.TokenFile, want)
	}
}

// TestBrokenAgentYMLStopsTheLoad: a broken agent.yml fails the start-up load
// (R5).
//
// Split: the old test also asserted that panel.CheckReport showed the parse
// error on the first screen; that check-report case moved to agentd
// (agentd/check.go), which owns the running agent. The loader refusal it pinned
// stays here, where the loader lives.
func TestBrokenAgentYMLStopsTheLoad(t *testing.T) {
	dir := t.TempDir()
	configPath := writeAgentOnlyConfig(t, dir, "state")
	agentPath := writeAgentYML(t, dir, "Panel: [\n")

	// Split: panel.LoadConfig -> config.Load.
	if _, err := Load(configPath); err == nil || !strings.Contains(err.Error(), agentPath) {
		t.Fatalf("Load err = %v, want it to name %s", err, agentPath)
	}
}

// TestAgentYMLBrokenDuringStartupIsRefused: the rule of the old Agent block
// still holds in the separated layout.
//
// Split: this is a pure loader case (it never constructs a Panel/Service), so
// it stays in config with panel.LoadConfig -> config.Load.
func TestAgentYMLBrokenDuringStartupIsRefused(t *testing.T) {
	dir := t.TempDir()
	// A static node keeps the "no Nodes and no Agent" rule out of the way, so
	// the Agent.Panel rule is the one that fires (as in the config.yml case).
	configPath := filepath.Join(dir, "config.yml")
	body := `Log: {Level: warning}
Nodes:
  - ApiConfig: {ApiHost: "https://p.example.com", ApiKey: k, NodeID: 1}
Agent:
  Enabled: true
  StateDir: state
`
	if err := os.WriteFile(configPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	writeAgentYML(t, dir, "Enabled: false\nPanel:\n  Enabled: true\n  URL: https://p.example.com\n  MachineID: 7\n  Token: t\n")
	// Split: panel.LoadConfig -> config.Load.
	if _, err := Load(configPath); err == nil || !strings.Contains(err.Error(), "requires Agent.Enabled") {
		t.Fatalf("err = %v", err)
	}
}

// TestLocalPolicyDefaultsThroughLoad: the new local gates are defined,
// defaulted and resolved by the load (only types and validation; the behaviour
// comes with the later packages).
//
// Split: the old name pinned panel.LoadConfig; the full loader is config.Load
// in this package.
func TestLocalPolicyDefaultsThroughLoad(t *testing.T) {
	dir := t.TempDir()
	configPath := writeAgentOnlyConfig(t, dir, "state")
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	a := cfg.Agent
	if !a.TerminalEnabled() || a.Terminal != nil {
		t.Errorf("Terminal must default to ON and stay unset in the config: %+v", a.Terminal)
	}
	if !a.XrayNodesEnabled() {
		t.Error("Modules.XrayNodes must default to on")
	}
	if a.Files == nil {
		t.Fatal("Files must be materialised")
	}
	want := []string{dir, filepath.Join(dir, "state")}
	if len(a.Files.Roots) != 2 || a.Files.Roots[0] != want[0] || a.Files.Roots[1] != want[1] {
		t.Errorf("Roots = %v, want %v", a.Files.Roots, want)
	}
	// The terminal defaults to ON, so the file manager follows it (PLAN v10's
	// three-state Files.Unrestricted): only AllowExec stays closed by default.
	if !a.UnrestrictedEnabled() || a.Files.AllowExec {
		t.Errorf("the file gates must follow the terminal default: %+v", a.Files)
	}
	excluded := a.ExcludedFiles()
	for i, wantEx := range []string{
		filepath.Join(dir, agentcfg.FileName),
		filepath.Join(dir, "state", "desired.json"),
		filepath.Join(dir, "state", "last_good.json"),
	} {
		if i >= len(excluded) || excluded[i] != wantEx {
			t.Errorf("ExcludedFiles()[%d] = %q, want %q", i, excluded[i], wantEx)
		}
	}
	// A root pointing at the agent's own file is refused.
	bad := writeAgentOnlyConfig(t, t.TempDir(), "state")
	writeAgentYML(t, filepath.Dir(bad), "Enabled: true\nFiles:\n  Roots: ["+filepath.ToSlash(filepath.Join(filepath.Dir(bad), agentcfg.FileName))+"]\n")
	if _, err := Load(bad); err == nil || !strings.Contains(err.Error(), "never managed") {
		t.Fatalf("err = %v, want the excluded-root refusal", err)
	}
	// A terminal limit above the hard cap is a config error, not a clamp.
	bad2 := writeAgentOnlyConfig(t, t.TempDir(), "state")
	writeAgentYML(t, filepath.Dir(bad2), "Enabled: true\nTerminal:\n  Enabled: true\n  MaxSessions: 9\n")
	if _, err := Load(bad2); err == nil || !strings.Contains(err.Error(), "MaxSessions") {
		t.Fatalf("err = %v, want the MaxSessions refusal", err)
	}
}
