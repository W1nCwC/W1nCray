package cmd

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/W1nCwC/W1nCray/agent/porthop"
)

type fakePorthopTool struct {
	st      porthop.Status
	cleared int
	err     error
}

func (f *fakePorthopTool) Inspect(context.Context) porthop.Status { return f.st }
func (f *fakePorthopTool) Clear(context.Context) error            { f.cleared++; return f.err }

func TestPorthopSubcommandsAreRegistered(t *testing.T) {
	for _, name := range []string{"status", "clear"} {
		c, _, err := rootCmd.Find([]string{"porthop", name})
		if err != nil || c == nil || c.Name() != name {
			t.Fatalf("porthop %s not registered: %v", name, err)
		}
	}
}

func TestPorthopStatusPrintsBackendAndRulesWithoutSecrets(t *testing.T) {
	f := &fakePorthopTool{st: porthop.Status{
		Enabled: true, Available: true, Backend: "nft", Note: "ipv6 nat unavailable, only IPv4 is redirected",
		Rules: []porthop.RuleStatus{
			{NodeID: 12, Proto: "udp", Ports: "20000-20100", To: 443, OK: true},
			{NodeID: 13, Proto: "udp", Ports: "21000-21100", To: 8443, Reason: "missing from the firewall"},
		},
	}}
	var out bytes.Buffer

	if err := porthopStatus(context.Background(), f, &out); err != nil {
		t.Fatal(err)
	}

	got := out.String()
	for _, want := range []string{"后端=nft", "规则=2", "节点 12", "20000-20100 -> 443  生效", "节点 13", "缺失", "ipv6 nat unavailable"} {
		if !strings.Contains(got, want) {
			t.Errorf("output lacks %q:\n%s", want, got)
		}
	}
	if f.cleared != 0 {
		t.Fatal("status must not clear anything")
	}
}

func TestPorthopStatusWithoutABackend(t *testing.T) {
	f := &fakePorthopTool{st: porthop.Status{LastError: "no usable firewall backend"}}
	var out bytes.Buffer

	if err := porthopStatus(context.Background(), f, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "无可用防火墙后端") || !strings.Contains(out.String(), "no usable firewall backend") {
		t.Fatalf("output = %q", out.String())
	}
}

func TestPorthopClearCallsTheManagerAndReportsFailures(t *testing.T) {
	f := &fakePorthopTool{}
	var out bytes.Buffer
	if err := porthopClear(context.Background(), f, &out); err != nil || f.cleared != 1 || !strings.Contains(out.String(), "已清除") {
		t.Fatalf("err = %v cleared = %d out = %q", err, f.cleared, out.String())
	}

	f = &fakePorthopTool{err: errors.New("boom")}
	if err := porthopClear(context.Background(), f, &out); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("a failed clear must be an error, got %v", err)
	}
}
