package bootstrap

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// TestXrayNodesHintSyncsTheKernelOnce is the happy path of ruling 6: with the
// local module on and the kernel wired, a "nodes" hint makes the kernel re-fetch
// this machine's node list exactly once (the kernel reloads only when the list
// changed, so changed=false is just as successful).
func TestXrayNodesHintSyncsTheKernelOnce(t *testing.T) {
	for _, changed := range []bool{false, true} {
		k := &fakeXray{syncChanged: changed}
		h := xrayNodeHint{enabled: true, xray: k, log: &recLog{}}
		if err := h.SyncXrayNodes(context.Background()); err != nil {
			t.Fatalf("SyncXrayNodes(changed=%v): %v", changed, err)
		}
		if got := k.syncCallCount(); got != 1 {
			t.Errorf("changed=%v: SyncMachineNodes called %d time(s), want 1", changed, got)
		}
	}
}

// TestXrayNodesHintRefusedWhenTheModuleIsOff covers the local gate: with
// Modules.XrayNodes false the hint is refused and the kernel is never asked, so
// a remote hint can never turn the module on (ruling 13).
func TestXrayNodesHintRefusedWhenTheModuleIsOff(t *testing.T) {
	k := &fakeXray{}
	log := &recLog{}
	h := xrayNodeHint{enabled: false, xray: k, log: log}
	err := h.SyncXrayNodes(context.Background())
	if !errors.Is(err, errXrayNodesDisabled) {
		t.Fatalf("err = %v, want errXrayNodesDisabled", err)
	}
	if got := k.syncCallCount(); got != 0 {
		t.Errorf("a refused hint called the kernel %d time(s)", got)
	}
	if !strings.Contains(log.warnText(), "refused") {
		t.Errorf("the refusal was not logged:\n%s", log.warnText())
	}
}

// TestXrayNodesHintDegradesWithoutTheKernel: a machine without the Xray kernel
// (a nil Service) must log a warning and return nil, so the hint degrades to the
// kernel's 60 s poll instead of failing a command or crashing the agent.
func TestXrayNodesHintDegradesWithoutTheKernel(t *testing.T) {
	log := &recLog{}
	h := xrayNodeHint{enabled: true, xray: nil, log: log}
	if err := h.SyncXrayNodes(context.Background()); err != nil {
		t.Fatalf("err = %v, want nil (degrade to the poll)", err)
	}
	if !strings.Contains(log.warnText(), "not installed") {
		t.Errorf("the degradation was not logged:\n%s", log.warnText())
	}
}

// TestXrayNodesHintDegradesWhenTheKernelCallFails: an old kernel (HTTP 404), an
// unreachable panel or a timeout is logged and degraded, never returned — the
// caller (agent/ws) must not treat it as a refused hint.
func TestXrayNodesHintDegradesWhenTheKernelCallFails(t *testing.T) {
	k := &fakeXray{syncErr: errors.New("Xray 内核节点同步接口返回 HTTP 404")}
	log := &recLog{}
	h := xrayNodeHint{enabled: true, xray: k, log: log}
	if err := h.SyncXrayNodes(context.Background()); err != nil {
		t.Fatalf("err = %v, want nil (degrade to the poll)", err)
	}
	if got := k.syncCallCount(); got != 1 {
		t.Errorf("SyncMachineNodes called %d time(s), want 1", got)
	}
	if !strings.Contains(log.warnText(), "404") || !strings.Contains(log.warnText(), "poll") {
		t.Errorf("the degradation was not logged:\n%s", log.warnText())
	}
}
