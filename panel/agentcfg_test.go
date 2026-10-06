package panel

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/agentcfg"
)

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

// TestLoadConfigRealV03FixtureStillLoads pins the compatibility promise: a real
// single-file config (the v0.3 fixture cmd/link_test.go uses) keeps loading
// byte for byte, with no agent configuration.
func TestLoadConfigRealV03FixtureStillLoads(t *testing.T) {
	cfg, err := LoadConfig(filepath.Join("..", "cmd", "testdata", "link_v03_real.yml"))
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
	cfg, err := LoadConfig(configPath)
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
	cfg, err := LoadConfig(configPath)
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

// TestBrokenAgentYMLStopsTheLoadAndIsReportedFirst: a broken agent.yml fails
// the start-up load, and "W1nCray check" shows it on the first screen (R5).
func TestBrokenAgentYMLStopsTheLoadAndIsReportedFirst(t *testing.T) {
	dir := t.TempDir()
	configPath := writeAgentOnlyConfig(t, dir, "state")
	agentPath := writeAgentYML(t, dir, "Panel: [\n")

	if _, err := LoadConfig(configPath); err == nil || !strings.Contains(err.Error(), agentPath) {
		t.Fatalf("LoadConfig err = %v, want it to name %s", err, agentPath)
	}

	var out bytes.Buffer
	items, err := CheckReport(configPath, false, &out)
	if err == nil {
		t.Fatalf("CheckReport passed:\n%s", out.String())
	}
	lines := strings.Split(out.String(), "\n")
	if len(lines) < 2 || !strings.HasPrefix(lines[0], "  agent.yml: ") {
		t.Fatalf("the first screen does not name agent.yml:\n%s", out.String())
	}
	if !strings.Contains(lines[1], "\u2717 agent.yml \u89e3\u6790\u5931\u8d25") {
		t.Fatalf("the parse error is not on the first screen:\n%s", out.String())
	}
	if len(items) == 0 {
		t.Error("CheckReport reported no failure item")
	}
}

// TestCheckReportNamesTheAgentYMLSource checks the successful report: the file,
// the winning source and the shadowed config.yml block.
func TestCheckReportNamesTheAgentYMLSource(t *testing.T) {
	dir := t.TempDir()
	configPath := writeAgentOnlyConfig(t, dir, "state-from-config")
	agentPath := writeAgentYML(t, dir, "Enabled: true\nStateDir: state-from-agentyml\n")

	var out bytes.Buffer
	if _, err := CheckReport(configPath, false, &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	report := out.String()
	for _, want := range []string{
		"agent.yml: " + agentPath,
		"\u2713 agent.yml \u5df2\u89e3\u6790",
		"Agent \u6bb5\u88ab agent.yml \u8986\u76d6",
		"\u6765\u6e90 " + agentPath,
	} {
		if !strings.Contains(report, want) {
			t.Errorf("the report does not contain %q:\n%s", want, report)
		}
	}
}

// TestAgentYMLBrokenDuringStartupIsRefused: the rule of the old Agent block
// still holds in the separated layout.
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
	if _, err := LoadConfig(configPath); err == nil || !strings.Contains(err.Error(), "requires Agent.Enabled") {
		t.Fatalf("err = %v", err)
	}
}

// TestLocalPolicyDefaultsThroughLoadConfig: the new local gates are defined,
// defaulted and resolved by the load (only types and validation; the behaviour
// comes with the later packages).
func TestLocalPolicyDefaultsThroughLoadConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := writeAgentOnlyConfig(t, dir, "state")
	cfg, err := LoadConfig(configPath)
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
	if a.Files.Unrestricted || a.Files.AllowExec {
		t.Errorf("the file gates must default to closed: %+v", a.Files)
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
	if _, err := LoadConfig(bad); err == nil || !strings.Contains(err.Error(), "never managed") {
		t.Fatalf("err = %v, want the excluded-root refusal", err)
	}
	// A terminal limit above the hard cap is a config error, not a clamp.
	bad2 := writeAgentOnlyConfig(t, t.TempDir(), "state")
	writeAgentYML(t, filepath.Dir(bad2), "Enabled: true\nTerminal:\n  Enabled: true\n  MaxSessions: 9\n")
	if _, err := LoadConfig(bad2); err == nil || !strings.Contains(err.Error(), "MaxSessions") {
		t.Fatalf("err = %v, want the MaxSessions refusal", err)
	}
}

// waitForConfig polls the running config until cond holds.
func waitForConfig(t *testing.T, p *Panel, timeout time.Duration, what string, cond func(*Config) bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		p.mu.Lock()
		ok := cond(p.cfg)
		p.mu.Unlock()
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestAgentYMLHotReload: the watcher follows agent.yml, a change takes effect,
// and a broken file is refused while the running configuration keeps serving
// (design T15 / R5).
func TestAgentYMLHotReload(t *testing.T) {
	dir := t.TempDir()
	configPath := writeAgentOnlyConfig(t, dir, "state-from-config")
	agentPath := writeAgentYML(t, dir, "Enabled: true\nStateDir: state-one\n")

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	p := New(configPath, cfg)
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	one := filepath.Join(dir, "state-one")
	waitForConfig(t, p, 10*time.Second, "the agent.yml state directory", func(c *Config) bool {
		return c.Agent != nil && c.Agent.StateDir == one
	})

	writeAgentYML(t, dir, "Enabled: true\nStateDir: state-two\n")
	two := filepath.Join(dir, "state-two")
	waitForConfig(t, p, 30*time.Second, "the hot-reloaded agent.yml", func(c *Config) bool {
		return c.Agent != nil && c.Agent.StateDir == two && c.AgentSource() == agentcfg.SourceAgentYML
	})

	// Break agent.yml: the reload must be refused and the running config kept.
	cap := captureLogs(t)
	if err := os.WriteFile(agentPath, []byte("Panel: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for !strings.Contains(cap.String(), "reload aborted") {
		if time.Now().After(deadline) {
			t.Fatalf("the broken agent.yml never triggered a reload attempt:\n%s", cap.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
	p.mu.Lock()
	got, running := p.cfg.Agent.StateDir, p.running
	p.mu.Unlock()
	if got != two || !running {
		t.Fatalf("after a broken agent.yml: state = %q, running = %v; want %q and true", got, running, two)
	}
}

// TestAgentYMLCreatedLaterIsPickedUp: the watcher registers agent.yml even
// before it exists, so switching to the separated layout needs no restart.
func TestAgentYMLCreatedLaterIsPickedUp(t *testing.T) {
	dir := t.TempDir()
	configPath := writeAgentOnlyConfig(t, dir, "state-from-config")
	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AgentSource() != agentcfg.SourceConfig {
		t.Fatalf("source = %q, want %q", cfg.AgentSource(), agentcfg.SourceConfig)
	}
	p := New(configPath, cfg)
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	agentPath := writeAgentYML(t, dir, "Enabled: true\nStateDir: state-from-agentyml\n")
	want := filepath.Join(dir, "state-from-agentyml")
	waitForConfig(t, p, 30*time.Second, "the newly created agent.yml", func(c *Config) bool {
		return c.Agent != nil && c.Agent.StateDir == want
	})
	p.mu.Lock()
	sourcePath := p.cfg.AgentSourcePath()
	p.mu.Unlock()
	if sourcePath != agentPath {
		t.Errorf("source path = %q, want %q", sourcePath, agentPath)
	}
}
