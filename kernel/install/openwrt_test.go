package install

import (
	"errors"
	"testing"

	"github.com/W1nCwC/W1nCray/kernel"
	"github.com/W1nCwC/W1nCray/kernel/manifest"
)

// TestSelectTargetOpenWrt covers target selection. On OpenWrt the order is
// openwrt_targets["linux/amd64"] (the current lite format), then the legacy
// targets["linux/amd64+openwrt"] key, then the generic targets["linux/amd64"].
// A machine that is not OpenWrt never reads openwrt_targets and never looks at
// the +openwrt key.
func TestSelectTargetOpenWrt(t *testing.T) {
	f := newFixture(t)
	// install.New copies the platform, so OpenWrt is set before the installer
	// is built (and toggled on the installer's own copy below).
	f.plat.OpenWrt = true
	in := f.installer(t.TempDir())
	generic := &manifest.Target{Variant: "musl"}
	legacy := &manifest.Target{Variant: "musl"}
	lite := &manifest.Target{Variant: "musl"}
	k := &manifest.Kernel{
		Name: "xray", Version: "0.6.0",
		Targets: map[string]*manifest.Target{
			"linux/amd64":         generic,
			"linux/amd64+openwrt": legacy,
		},
		OpenWrtTargets: map[string]*manifest.Target{"linux/amd64": lite},
	}

	// New format: openwrt_targets wins over the legacy +openwrt key and over
	// the generic build.
	key, tg, err := in.selectTarget(k)
	if err != nil {
		t.Fatalf("OpenWrt selectTarget: %v", err)
	}
	if key != "linux/amd64" || tg != lite {
		t.Fatalf("OpenWrt picked %q (%p), want openwrt_targets[linux/amd64] (%p)", key, tg, lite)
	}

	// A manifest signed before openwrt_targets existed still gets its lite
	// build from the legacy +openwrt key.
	k.OpenWrtTargets = nil
	key, tg, err = in.selectTarget(k)
	if err != nil {
		t.Fatalf("legacy selectTarget: %v", err)
	}
	if key != "linux/amd64" || tg != legacy {
		t.Fatalf("legacy picked %q (%p), want linux/amd64+openwrt (%p)", key, tg, legacy)
	}

	// An OpenWrt machine falls back to the generic build when the manifest has
	// neither openwrt_targets nor a +openwrt key.
	delete(k.Targets, "linux/amd64+openwrt")
	key, tg, err = in.selectTarget(k)
	if err != nil || key != "linux/amd64" || tg != generic {
		t.Fatalf("fallback picked %q (%p), err=%v", key, tg, err)
	}

	// A non-OpenWrt machine never reads openwrt_targets, even when the legacy
	// +openwrt key is present too.
	in.plat.OpenWrt = false
	k.OpenWrtTargets = map[string]*manifest.Target{"linux/amd64": lite}
	k.Targets["linux/amd64+openwrt"] = legacy
	key, tg, err = in.selectTarget(k)
	if err != nil {
		t.Fatalf("non-OpenWrt selectTarget: %v", err)
	}
	if key != "linux/amd64" || tg != generic {
		t.Fatalf("non-OpenWrt picked %q (%p), want linux/amd64 (%p)", key, tg, generic)
	}

	// A kernel that only ships an OpenWrt build is unavailable off OpenWrt.
	only := &manifest.Kernel{
		Name: "xray", Version: "0.6.0",
		Targets:        map[string]*manifest.Target{},
		OpenWrtTargets: map[string]*manifest.Target{"linux/amd64": lite},
	}
	if _, _, err := in.selectTarget(only); !errors.Is(err, kernel.ErrUnavailable) {
		t.Fatalf("non-OpenWrt on an OpenWrt-only kernel: %v", err)
	}
}
