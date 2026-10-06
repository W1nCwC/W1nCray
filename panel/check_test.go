package panel

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCheckReportMatchesCheckOutput pins the refactor behind link's baseline
// comparison: CheckReport reports the failure items Check prints, and both the
// output and the error of Check stay exactly what they were.
func TestCheckReportMatchesCheckOutput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	body := `Log: {Level: warning}
RouteConfigPath: ` + filepath.ToSlash(filepath.Join(dir, "missing-route.json")) + `
Nodes:
  - PanelType: "Xboard"
    ApiConfig:
      ApiHost: "https://panel.example.com"
      ApiKey: "k"
      NodeID: 173
      NodeType: V2ray
    ControllerConfig:
      CertConfig:
        CertMode: none
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	var checkOut bytes.Buffer
	checkErr := Check(path, false, &checkOut)
	if checkErr == nil {
		t.Fatalf("Check passed on a config with a missing route.json:\n%s", checkOut.String())
	}

	var reportOut bytes.Buffer
	items, reportErr := CheckReport(path, false, &reportOut)
	if reportErr == nil || reportErr.Error() != checkErr.Error() {
		t.Fatalf("CheckReport error = %v, Check error = %v", reportErr, checkErr)
	}
	if reportOut.String() != checkOut.String() {
		t.Errorf("CheckReport output differs from Check:\n--- CheckReport ---\n%s\n--- Check ---\n%s", reportOut.String(), checkOut.String())
	}
	if len(items) == 0 {
		t.Fatal("CheckReport reported no failure items")
	}
	for _, it := range items {
		if !strings.Contains(checkOut.String(), it) {
			t.Errorf("failure item %q does not appear in Check's output", it)
		}
	}
}

// TestCheckReportOnUnloadableConfig: a config that cannot even be loaded is a
// single failure item, and Check's error is unchanged.
func TestCheckReportOnUnloadableConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte("Nodes: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	items, err := CheckReport(path, false, &out)
	if err == nil {
		t.Fatal("CheckReport accepted an unparsable config")
	}
	if len(items) != 1 || items[0] != err.Error() {
		t.Errorf("items = %v, want just the loader error %q", items, err.Error())
	}
	if Check(path, false, &bytes.Buffer{}) == nil {
		t.Error("Check accepted an unparsable config")
	}
}
