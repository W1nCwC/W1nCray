package bootstrap

import (
	"runtime"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/agentcfg"
	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/spec"
	"github.com/W1nCwC/W1nCray/driver/frp"
	"github.com/W1nCwC/W1nCray/driver/gost"
)

// TestDriverReadyTimeoutWiring covers D4/F6's wiring: buildDrivers hands both
// supervised drivers the shared default for this machine (15s on amd64/arm64
// off OpenWrt, 60s on the slower architectures and on every architecture
// running OpenWrt), and replaces it with the agent.yml override when one is
// set. The readiness limits were hard-coded before (frp 15s, gost 10s), which
// the v11 D4/T2 runs measured as too tight on MIPS/ARM routers.
func TestDriverReadyTimeoutWiring(t *testing.T) {
	for _, openWrt := range []bool{false, true} {
		name := "linux"
		if openWrt {
			name = "openwrt"
		}
		t.Run(name, func(t *testing.T) {
			drivers, err := buildDrivers(spec.Policy{}, nil, openWrt, nil)
			if err != nil {
				t.Fatal(err)
			}
			want := driver.DefaultReadyTimeout(runtime.GOARCH, openWrt)
			fd, ok := drivers[spec.EngineFrp].(*frp.Driver)
			if !ok {
				t.Fatalf("frp driver = %T", drivers[spec.EngineFrp])
			}
			if got := fd.ReadyTimeout(); got != want {
				t.Errorf("frp readiness default = %s, want %s (GOARCH %s, openWrt %v)", got, want, runtime.GOARCH, openWrt)
			}
			gd, ok := drivers[spec.EngineGost].(*gost.Driver)
			if !ok {
				t.Fatalf("gost driver = %T", drivers[spec.EngineGost])
			}
			if got := gd.ReadyTimeout(); got != want {
				t.Errorf("gost readiness default = %s, want %s (GOARCH %s, openWrt %v)", got, want, runtime.GOARCH, openWrt)
			}
		})
	}

	// The two overrides are independent and win over the OpenWrt default.
	cfg := &agentcfg.Config{Drivers: &agentcfg.DriversConfig{
		Frp:  &agentcfg.FrpConfig{ReadyTimeoutSec: 90},
		Gost: &agentcfg.GostConfig{ReadyTimeoutSec: 45},
	}}
	over, err := buildDrivers(spec.Policy{}, cfg, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	fd, ok := over[spec.EngineFrp].(*frp.Driver)
	if !ok {
		t.Fatalf("frp driver = %T", over[spec.EngineFrp])
	}
	if got := fd.ReadyTimeout(); got != 90*time.Second {
		t.Errorf("agent.yml frp override = %s, want 1m30s", got)
	}
	gd, ok := over[spec.EngineGost].(*gost.Driver)
	if !ok {
		t.Fatalf("gost driver = %T", over[spec.EngineGost])
	}
	if got := gd.ReadyTimeout(); got != 45*time.Second {
		t.Errorf("agent.yml gost override = %s, want 45s", got)
	}

	// A gost-only override must not touch frp.
	only := &agentcfg.Config{Drivers: &agentcfg.DriversConfig{Gost: &agentcfg.GostConfig{ReadyTimeoutSec: 45}}}
	one, err := buildDrivers(spec.Policy{}, only, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if d := one[spec.EngineFrp].(*frp.Driver); d.ReadyTimeout() != driver.DefaultReadyTimeout(runtime.GOARCH, false) {
		t.Errorf("a gost override changed frp to %s", d.ReadyTimeout())
	}
}
