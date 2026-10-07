package install

import (
	"testing"

	"github.com/W1nCwC/W1nCray/kernel/manifest"
)

// TestSelectTargetOpenWrt covers PLAN v11 §E target selection: on OpenWrt the
// linux/<arch>+openwrt key wins, the generic key is the fallback, and a machine
// that is not OpenWrt never looks at the +openwrt key.
func TestSelectTargetOpenWrt(t *testing.T) {
	f := newFixture(t)
	// install.New copies the platform, so OpenWrt is set before the installer
	// is built (and toggled on the installer's own copy below).
	f.plat.OpenWrt = true
	in := f.installer(t.TempDir())
	generic := &manifest.Target{Variant: "musl"}
	lite := &manifest.Target{Variant: "musl"}
	k := &manifest.Kernel{
		Name: "xray", Version: "0.6.0",
		Targets: map[string]*manifest.Target{
			"linux/amd64":         generic,
			"linux/amd64+openwrt": lite,
		},
	}

	key, tg, err := in.selectTarget(k)
	if err != nil {
		t.Fatalf("OpenWrt selectTarget: %v", err)
	}
	if key != "linux/amd64+openwrt" || tg != lite {
		t.Fatalf("OpenWrt picked %q (%p), want linux/amd64+openwrt (%p)", key, tg, lite)
	}

	in.plat.OpenWrt = false
	key, tg, err = in.selectTarget(k)
	if err != nil {
		t.Fatalf("selectTarget: %v", err)
	}
	if key != "linux/amd64" || tg != generic {
		t.Fatalf("non-OpenWrt picked %q (%p), want linux/amd64 (%p)", key, tg, generic)
	}

	// An OpenWrt machine falls back to the generic build when the manifest has
	// no lite variant.
	delete(k.Targets, "linux/amd64+openwrt")
	in.plat.OpenWrt = true
	key, _, err = in.selectTarget(k)
	if err != nil || key != "linux/amd64" {
		t.Fatalf("fallback picked %q, err=%v", key, err)
	}
}
