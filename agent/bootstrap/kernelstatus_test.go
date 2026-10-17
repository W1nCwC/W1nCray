package bootstrap

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/W1nCwC/W1nCray/agent/wsproto"
	"github.com/W1nCwC/W1nCray/agent/xrayapi"
)

func TestApplyKernelStatusCarriesTheRuntimeProfileState(t *testing.T) {
	now := time.Unix(1_000_100, 0)
	comp := wsproto.Component{Name: xrayapi.KernelName, Kind: "kernel", State: wsproto.StateRunning}
	applyKernelStatus(&comp, xrayapi.Status{
		Version:        "0.9.0",
		StartedAt:      1_000_000,
		Running:        true,
		Nodes:          []xrayapi.NodeStatus{{Tag: "n1", Online: 3}, {Tag: "n2", Error: "boom"}},
		Runtime:        "panel",
		RuntimeVersion: "abc123",
		RuntimeError:   "profile def456 refused by xray: bad outbound",
	}, now)

	if comp.Version != "0.9.0" || comp.UptimeS != 100 || comp.State != wsproto.StateRunning {
		t.Fatalf("version/uptime/state = %q/%d/%q", comp.Version, comp.UptimeS, comp.State)
	}
	if len(comp.Instances) != 2 || comp.Instances[0].Conns != 3 || comp.Instances[1].State != wsproto.StateFailed {
		t.Fatalf("instances = %+v", comp.Instances)
	}
	if comp.Runtime != "panel" || comp.RuntimeVersion != "abc123" || comp.RuntimeError != "profile def456 refused by xray: bad outbound" {
		t.Fatalf("runtime = %q/%q/%q", comp.Runtime, comp.RuntimeVersion, comp.RuntimeError)
	}

	raw, err := json.Marshal(comp)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"runtime":"panel"`, `"runtime_version":"abc123"`, `"runtime_error":`} {
		if !strings.Contains(string(raw), key) {
			t.Fatalf("wire %s lacks %s", raw, key)
		}
	}
}

func TestApplyKernelStatusFromAnOlderKernelAddsNoRuntimeKeys(t *testing.T) {
	comp := wsproto.Component{Name: xrayapi.KernelName, Kind: "kernel", Version: "0.8.9", State: wsproto.StateRunning}
	applyKernelStatus(&comp, xrayapi.Status{Version: "0.8.9", Running: false}, time.Unix(10, 0))

	if comp.State != wsproto.StateFailed {
		t.Fatalf("a kernel that is not running must be failed, got %q", comp.State)
	}
	raw, err := json.Marshal(comp)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "runtime") {
		t.Fatalf("an older kernel must not produce runtime keys: %s", raw)
	}
}

func TestApplyKernelStatusCapsTheRuntimeErrorOnARuneBoundary(t *testing.T) {
	long := strings.Repeat("错", maxRuntimeErrorBytes) // 3 bytes per rune
	comp := wsproto.Component{}
	applyKernelStatus(&comp, xrayapi.Status{Running: true, Runtime: "panel", RuntimeError: long}, time.Unix(0, 0))

	if len(comp.RuntimeError) > maxRuntimeErrorBytes || len(comp.RuntimeError) < maxRuntimeErrorBytes-3 {
		t.Fatalf("capped length = %d", len(comp.RuntimeError))
	}
	if !utf8.ValidString(comp.RuntimeError) {
		t.Fatal("the cap split a rune")
	}
}
