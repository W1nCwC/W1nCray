package xraynode

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/W1nCwC/W1nCray/agent/filesync"
)

// TestCheckStagedNamesTheBrokenFile covers the CLI-facing entry point: the
// staged file set is validated against the live config file (no running
// instance needed) and a broken file is named.
func TestCheckStagedNamesTheBrokenFile(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(configPath, []byte("Log: {Level: warning}\nAgent:\n  Enabled: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(dir, "stage")
	if err := os.MkdirAll(stage, 0o755); err != nil {
		t.Fatal(err)
	}
	route := filepath.Join(stage, filesync.NameRoute)

	if err := os.WriteFile(route, []byte(`{"rules":[{"type":"field","not_a_field":"x"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	errs := CheckStaged(context.Background(), configPath, stage, []string{filesync.NameRoute})
	if len(errs) == 0 {
		t.Fatal("a broken route.json was accepted")
	}
	if joined := joinErrors(errs); !strings.Contains(joined, filesync.NameRoute) || !strings.Contains(joined, "rules[0]") {
		t.Errorf("errors = %v, want the file name and the rule index", errs)
	}

	if err := os.WriteFile(route, []byte(`{"rules":[{"type":"field","outboundTag":"direct","domain":["example.com"]}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if errs := CheckStaged(context.Background(), configPath, stage, []string{filesync.NameRoute}); len(errs) > 0 {
		t.Fatalf("a valid route.json was refused: %v", errs)
	}

	// A name whose staged copy is missing is refused, never silently skipped.
	errs = CheckStaged(context.Background(), configPath, stage, []string{filesync.NameDNS})
	if len(errs) == 0 || !strings.Contains(joinErrors(errs), filesync.NameDNS) {
		t.Errorf("a missing staged copy was not named: %v", errs)
	}
}
