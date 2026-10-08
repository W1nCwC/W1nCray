package agentd

import (
	"os"
	"path/filepath"
	"testing"
)

// loadLocalAgentConfig writes a config.yml plus an agent.yml and loads them the way
// the daemon, agent-apply and `W1nCray xray` do.
func loadLocalAgentConfig(t *testing.T, agentYML string) *Config {
	t.Helper()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(configPath, []byte("Log: {Level: warning}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if agentYML != "" {
		if err := os.WriteFile(filepath.Join(dir, "agent.yml"), []byte(agentYML), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// TestKernelAllowHTTPComesFromTheLocalFile covers D-M1 end to end at the
// wiring level: the switch only exists in the machine's own configuration, the
// default is off, and the value the daemon/agent-apply/xray command hand to
// bootstrap.Options is exactly the local file's.
func TestKernelAllowHTTPComesFromTheLocalFile(t *testing.T) {
	if KernelAllowHTTP(nil) {
		t.Error("a nil config must not permit http kernel sources")
	}
	if KernelAllowHTTP(loadLocalAgentConfig(t, "Enabled: true\n")) {
		t.Error("a machine that never wrote the switch must stay https-only")
	}
	if KernelAllowHTTP(loadLocalAgentConfig(t, "Enabled: true\nKernels:\n  AllowHTTP: false\n")) {
		t.Error("Kernels.AllowHTTP: false must stay https-only")
	}
	if !KernelAllowHTTP(loadLocalAgentConfig(t, "Enabled: true\nKernels:\n  AllowHTTP: true\n")) {
		t.Error("agent.yml Kernels.AllowHTTP: true did not reach the wiring")
	}
}
