package panel

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/W1nCwC/W1nCray/agent/filesync"
)

// newValidatorRig builds a panel whose config.yml only enables the agent (no
// static nodes), so the validator can be exercised without a panel connection.
func newValidatorRig(t *testing.T, configBody string) (*Panel, string, string) {
	t.Helper()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	p := New(configPath, cfg)
	stage := filepath.Join(dir, "stage")
	if err := os.MkdirAll(stage, 0o755); err != nil {
		t.Fatal(err)
	}
	return p, configPath, stage
}

// TestCoreValidatorNamesTheBrokenRouteRule covers acceptance 4 with the real
// xray kernel: an illegal route.json is refused and the error names the file
// and the rule index.
func TestCoreValidatorNamesTheBrokenRouteRule(t *testing.T) {
	p, _, stage := newValidatorRig(t, "Log: {Level: warning}\nAgent:\n  Enabled: true\n")
	if err := os.WriteFile(filepath.Join(stage, filesync.NameRoute), []byte(`{"rules":[{"type":"field","not_a_field":"x"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	v := p.NewCoreValidator()
	errs := v.ValidateStaged(context.Background(), stage, []filesync.FileRef{{Name: filesync.NameRoute}})
	if len(errs) == 0 {
		t.Fatal("an illegal route.json was accepted")
	}
	joined := joinErrors(errs)
	if !strings.Contains(joined, "route.json") || !strings.Contains(joined, "rules[0]") {
		t.Errorf("errors = %v, want the file name and the rule index", errs)
	}
}

// TestCoreValidatorAcceptsAGoodRoute: the happy path must not report anything.
func TestCoreValidatorAcceptsAGoodRoute(t *testing.T) {
	p, _, stage := newValidatorRig(t, "Log: {Level: warning}\nAgent:\n  Enabled: true\n")
	if err := os.WriteFile(filepath.Join(stage, filesync.NameRoute), []byte(`{"rules":[{"type":"field","outboundTag":"direct","domain":["example.com"]}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if errs := p.NewCoreValidator().ValidateStaged(context.Background(), stage, []filesync.FileRef{{Name: filesync.NameRoute}}); len(errs) > 0 {
		t.Fatalf("a valid route.json was refused: %v", errs)
	}
}

// TestCoreValidatorNeverBindsPorts pins the rule the design depends on (design
// section 3.4 step 3b): the pre-check builds the instance but never starts it,
// so a port another process already holds is not an error.
func TestCoreValidatorNeverBindsPorts(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	p, _, stage := newValidatorRig(t, "Log: {Level: warning}\nAgent:\n  Enabled: true\n")
	inbound := fmt.Sprintf(`[{"tag":"probe","listen":"127.0.0.1","port":%d,"protocol":"dokodemo-door","settings":{"address":"1.1.1.1","port":80,"network":"tcp"}}]`, port)
	if err := os.WriteFile(filepath.Join(stage, filesync.NameCustomInbound), []byte(inbound), 0o644); err != nil {
		t.Fatal(err)
	}
	errs := p.NewCoreValidator().ValidateStaged(context.Background(), stage, []filesync.FileRef{{Name: filesync.NameCustomInbound}})
	if len(errs) > 0 {
		t.Fatalf("the pre-check bound a port (or refused a good config): %v", errs)
	}
	// The listener still owns the port: nothing was closed or replaced.
	if _, err := net.Dial("tcp", ln.Addr().String()); err != nil {
		t.Fatalf("the occupied port stopped accepting: %v", err)
	}
}

// TestCoreValidatorPreChecksAStagedConfigYML covers ruling 2: a staged
// config.yml goes through the full LoadConfig, so a broken one is refused
// before it is written.
func TestCoreValidatorPreChecksAStagedConfigYML(t *testing.T) {
	p, _, stage := newValidatorRig(t, "Log: {Level: warning}\nAgent:\n  Enabled: true\n")

	good := "Log: {Level: warning}\nAgent:\n  Enabled: true\n  StateDir: state\n"
	if err := os.WriteFile(filepath.Join(stage, filesync.NameConfig), []byte(good), 0o644); err != nil {
		t.Fatal(err)
	}
	if errs := p.NewCoreValidator().ValidateStaged(context.Background(), stage, []filesync.FileRef{{Name: filesync.NameConfig}}); len(errs) > 0 {
		t.Fatalf("a valid config.yml was refused: %v", errs)
	}

	// No Nodes and no Agent: LoadConfig refuses it.
	bad := "Log: {Level: warning}\n"
	if err := os.WriteFile(filepath.Join(stage, filesync.NameConfig), []byte(bad), 0o644); err != nil {
		t.Fatal(err)
	}
	errs := p.NewCoreValidator().ValidateStaged(context.Background(), stage, []filesync.FileRef{{Name: filesync.NameConfig}})
	if len(errs) == 0 {
		t.Fatal("a config.yml that cannot load was accepted")
	}
	if !strings.Contains(joinErrors(errs), "config.yml") {
		t.Errorf("errors = %v, want the file name", errs)
	}
	// The pre-check copy must not survive.
	entries, err := os.ReadDir(filepath.Dir(p.path))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".w1ncray-precheck-") {
			t.Errorf("the pre-check copy %s survived", e.Name())
		}
	}
}

// TestCoreValidatorRefusesAStagedCopyThatIsNotThere: a file listed but not
// staged is an error, never silently skipped.
func TestCoreValidatorRefusesAStagedCopyThatIsNotThere(t *testing.T) {
	p, _, stage := newValidatorRig(t, "Log: {Level: warning}\nAgent:\n  Enabled: true\n")
	errs := p.NewCoreValidator().ValidateStaged(context.Background(), stage, []filesync.FileRef{{Name: filesync.NameDNS}})
	if len(errs) == 0 || !strings.Contains(joinErrors(errs), "missing") {
		t.Fatalf("errors = %v, want a missing staged copy", errs)
	}
}

func joinErrors(errs []error) string {
	parts := make([]string, len(errs))
	for i, e := range errs {
		parts[i] = e.Error()
	}
	return strings.Join(parts, "; ")
}
