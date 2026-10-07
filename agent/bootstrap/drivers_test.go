package bootstrap

import (
	"runtime"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/agentcfg"
	"github.com/W1nCwC/W1nCray/agent/spec"
	"github.com/W1nCwC/W1nCray/driver/frp"
)

// TestFrpReadyTimeoutWiring covers D4's wiring: buildDrivers gives the frp
// driver the architecture default (15s on amd64/arm64, 60s elsewhere), and an
// agent.yml override (Drivers.Frp.ReadyTimeoutSec) replaces it. The readiness
// limit was hard-coded to 15s before, which the v11 D4 run measured as too
// tight on MIPS/ARM routers.
func TestFrpReadyTimeoutWiring(t *testing.T) {
	drivers, err := buildDrivers(spec.Policy{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	d, ok := drivers[spec.EngineFrp].(*frp.Driver)
	if !ok {
		t.Fatalf("frp driver = %T", drivers[spec.EngineFrp])
	}
	if got, want := d.ReadyTimeout(), frp.DefaultReadyTimeout(runtime.GOARCH); got != want {
		t.Errorf("frp readiness default = %s, want the %s default %s", got, runtime.GOARCH, want)
	}

	cfg := &agentcfg.Config{Drivers: &agentcfg.DriversConfig{Frp: &agentcfg.FrpConfig{ReadyTimeoutSec: 90}}}
	over, err := buildDrivers(spec.Policy{}, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	od, ok := over[spec.EngineFrp].(*frp.Driver)
	if !ok {
		t.Fatalf("frp driver = %T", over[spec.EngineFrp])
	}
	if got := od.ReadyTimeout(); got != 90*time.Second {
		t.Errorf("agent.yml override = %s, want 1m30s", got)
	}
}
