package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/W1nCwC/W1nCray/agent/agentcfg"
)

// splitFixture is a machine that is already in machine mode: every node entry
// was commented out by an earlier conversion (the landing VPS layout) and the
// agent configuration still lives in the Agent: block of config.yml.
func splitFixture(t *testing.T) string {
	t.Helper()
	return linkFixturePrelude +
		"#MIGRATED-2026-10-06 node 119 runs in machine mode\n" + commentEntry(t, linkEntry119) + "\n" +
		`
Agent:
  Enabled: true
  StateDir: state
  # local policy
  Policy:
    AllowListen: ["0.0.0.0"]
    PortRange: [20000, 40000]
  Panel:
    Enabled: true
    URL: https://panel.example.com
    MachineID: 3
    TokenFile: agent.token
    MachineNodes: true
    NodeControllers:
      119:
        ListenIP: 0.0.0.0   # keep
        SendIP: 0.0.0.0
        CertConfig:
          CertMode: none

# trailing comment that belongs to the file, not to the block
`
}

func writeSplitFixture(t *testing.T) (dir, cfgPath string) {
	t.Helper()
	dir, cfgPath = writeLinkFixture(t, splitFixture(t))
	if err := os.WriteFile(filepath.Join(dir, "agent.token"), []byte(linkTestToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, cfgPath
}

func decodeAgentBlock(t *testing.T, cfgText string) any {
	t.Helper()
	var whole map[string]any
	if err := yaml.Unmarshal([]byte(cfgText), &whole); err != nil {
		t.Fatal(err)
	}
	return whole["Agent"]
}

func TestLinkSplitMovesTheAgentBlockVerbatim(t *testing.T) {
	dir, cfgPath := writeSplitFixture(t)
	before := decodeAgentBlock(t, splitFixture(t))

	var out bytes.Buffer
	if err := runSplit(cfgPath, linkOptions{Split: true, SkipCheck: true}, &out); err != nil {
		t.Fatalf("split: %v\n%s", err, out.String())
	}

	agentText, err := os.ReadFile(filepath.Join(dir, agentcfg.FileName))
	if err != nil {
		t.Fatal(err)
	}
	var moved map[string]any
	if err := yaml.Unmarshal(agentText, &moved); err != nil {
		t.Fatalf("agent.yml is not YAML: %v\n%s", err, agentText)
	}
	if !reflect.DeepEqual(before, any(moved)) {
		t.Errorf("agent.yml decodes differently from the old Agent: block\nbefore: %#v\nafter:  %#v", before, moved)
	}
	if !strings.Contains(string(agentText), "ListenIP: 0.0.0.0   # keep") {
		t.Errorf("inline comments were not kept:\n%s", agentText)
	}
	if fi, _ := os.Stat(filepath.Join(dir, agentcfg.FileName)); fi == nil || (fi.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/') {
		t.Errorf("agent.yml must be 0600")
	}

	cfgText, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if decodeAgentBlock(t, string(cfgText)) != nil {
		t.Errorf("config.yml still has an Agent: block:\n%s", cfgText)
	}
	for _, keep := range []string{"# W1nCray config (fixture)", "ConnectionConfig:", "#MIGRATED-2026-10-06", "# trailing comment that belongs to the file", "# Agent: moved to agent.yml"} {
		if !strings.Contains(string(cfgText), keep) {
			t.Errorf("config.yml lost %q:\n%s", keep, cfgText)
		}
	}
	if strings.Contains(string(cfgText), "NodeControllers") {
		t.Errorf("the moved block is still in config.yml:\n%s", cfgText)
	}

	// The agent loads it as the separated layout and sees the same settings.
	cfg, err := agentcfg.Load(filepath.Join(dir, agentcfg.FileName))
	if err != nil {
		t.Fatalf("agent.yml does not load: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("agent.yml does not validate: %v", err)
	}
	if cfg.Panel == nil || cfg.Panel.MachineID != 3 || len(cfg.Panel.NodeControllerIDs()) != 1 {
		t.Errorf("panel settings were not carried over: %+v", cfg.Panel)
	}
	if !cfg.TerminalEnabled() {
		t.Errorf("the terminal must stay ON by default")
	}

	// A backup of the original config exists and is byte-identical.
	matches, _ := filepath.Glob(cfgPath + ".bak-link-*")
	if len(matches) != 1 {
		t.Fatalf("backups: %v", matches)
	}
	if b, _ := os.ReadFile(matches[0]); string(b) != splitFixture(t) {
		t.Errorf("the backup is not the original config")
	}
}

func TestLinkSplitNoTerminal(t *testing.T) {
	dir, cfgPath := writeSplitFixture(t)
	var out bytes.Buffer
	if err := runSplit(cfgPath, linkOptions{Split: true, SkipCheck: true, NoTerminal: true}, &out); err != nil {
		t.Fatalf("split: %v\n%s", err, out.String())
	}
	cfg, err := agentcfg.Load(filepath.Join(dir, agentcfg.FileName))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TerminalEnabled() {
		t.Errorf("--noterminal must disable the terminal")
	}
}

func TestLinkSplitRefusesAnExistingAgentYMLWithoutForce(t *testing.T) {
	dir, cfgPath := writeSplitFixture(t)
	agentPath := filepath.Join(dir, agentcfg.FileName)
	if err := os.WriteFile(agentPath, []byte("Enabled: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runSplit(cfgPath, linkOptions{Split: true, SkipCheck: true}, &out); err == nil {
		t.Fatal("split overwrote an existing agent.yml without --force")
	}
	if b, _ := os.ReadFile(cfgPath); string(b) != splitFixture(t) {
		t.Errorf("config.yml changed on a refusal")
	}
	if b, _ := os.ReadFile(agentPath); string(b) != "Enabled: true\n" {
		t.Errorf("agent.yml changed on a refusal")
	}
}

func TestLinkSplitDryRunWritesNothing(t *testing.T) {
	dir, cfgPath := writeSplitFixture(t)
	var out bytes.Buffer
	if err := runSplit(cfgPath, linkOptions{Split: true, DryRun: true}, &out); err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, agentcfg.FileName)); err == nil {
		t.Errorf("dry-run wrote agent.yml")
	}
	if b, _ := os.ReadFile(cfgPath); string(b) != splitFixture(t) {
		t.Errorf("dry-run changed config.yml")
	}
	if m, _ := filepath.Glob(cfgPath + ".bak-link-*"); len(m) != 0 {
		t.Errorf("dry-run wrote a backup")
	}
}

func TestLinkSplitWithoutAnAgentBlock(t *testing.T) {
	_, cfgPath := writeLinkFixture(t, linkFixture)
	var out bytes.Buffer
	if err := runSplit(cfgPath, linkOptions{Split: true, SkipCheck: true}, &out); err == nil {
		t.Fatal("split accepted a config without an Agent: block")
	}
}

func TestLinkSplitRefusesATerminalConflict(t *testing.T) {
	text := strings.Replace(splitFixture(t), "  Enabled: true\n  StateDir", "  Enabled: true\n  Terminal: {Enabled: true}\n  StateDir", 1)
	dir, cfgPath := writeLinkFixture(t, text)
	var out bytes.Buffer
	if err := runSplit(cfgPath, linkOptions{Split: true, SkipCheck: true, NoTerminal: true}, &out); err == nil {
		t.Fatal("--noterminal silently overrode an explicit Terminal setting")
	}
	if _, err := os.Stat(filepath.Join(dir, agentcfg.FileName)); err == nil {
		t.Errorf("agent.yml was written on a refusal")
	}
}

func TestLinkSplitCRLF(t *testing.T) {
	text := strings.ReplaceAll(splitFixture(t), "\n", "\r\n")
	dir, cfgPath := writeLinkFixture(t, text)
	var out bytes.Buffer
	if err := runSplit(cfgPath, linkOptions{Split: true, SkipCheck: true}, &out); err != nil {
		t.Fatalf("split CRLF: %v\n%s", err, out.String())
	}
	b, _ := os.ReadFile(cfgPath)
	if strings.Contains(strings.ReplaceAll(string(b), "\r\n", ""), "\n") {
		t.Errorf("config.yml mixes line endings after the split")
	}
	if _, err := agentcfg.Load(filepath.Join(dir, agentcfg.FileName)); err != nil {
		t.Errorf("agent.yml from a CRLF config does not load: %v", err)
	}
}

// With the full offline check on: problems the fixture already had (it has no
// geo files, for example) must not block the split, and the split itself must
// not add one.
func TestLinkSplitWithTheFullCheck(t *testing.T) {
	dir, cfgPath := writeSplitFixture(t)
	var out bytes.Buffer
	if err := runSplit(cfgPath, linkOptions{Split: true}, &out); err != nil {
		t.Fatalf("split with the full check: %v\n%s", err, out.String())
	}
	if _, err := os.Stat(filepath.Join(dir, agentcfg.FileName)); err != nil {
		t.Fatalf("agent.yml missing: %v", err)
	}
	if strings.Contains(out.String(), "已自动恢复") {
		t.Errorf("the split was rolled back:\n%s", out.String())
	}
}
