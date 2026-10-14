package frp

import (
	"runtime"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
)

// TestDefaultReadyTimeoutIsPerArchitecture covers D4's table as frp uses it:
// 15s on the fast 64-bit targets and 60s everywhere else. F6 moved the table
// into agent/driver (shared with gost) and added the OpenWrt rule, so this test
// now pins the driver's view of it (OpenWrt=false keeps arm64 at 15s). The
// full architecture x OpenWrt matrix lives in driver.TestDefaultReadyTimeout.
func TestDefaultReadyTimeoutIsPerArchitecture(t *testing.T) {
	for _, tc := range []struct {
		goarch string
		want   time.Duration
	}{
		{"amd64", 15 * time.Second},
		{"arm64", 15 * time.Second},
		{"386", 60 * time.Second},
		{"arm", 60 * time.Second},
		{"mips", 60 * time.Second},
		{"mipsle", 60 * time.Second},
		{"mips64le", 60 * time.Second},
		{"riscv64", 60 * time.Second},
	} {
		if got := driver.DefaultReadyTimeout(tc.goarch, false); got != tc.want {
			t.Errorf("DefaultReadyTimeout(%q, openWrt=false) = %s, want %s", tc.goarch, got, tc.want)
		}
	}
	// F6: on OpenWrt even amd64/arm64 take the slow path, because the CPU is a
	// router CPU (MT7981 class) and not a server one.
	for _, goarch := range []string{"amd64", "arm64", "mipsle", "arm"} {
		if got := driver.DefaultReadyTimeout(goarch, true); got != 60*time.Second {
			t.Errorf("DefaultReadyTimeout(%q, openWrt=true) = %s, want 1m0s", goarch, got)
		}
	}
}

// TestNewUsesTheArchitectureDefaultAndTheOverride covers the two ways the
// readiness limit is chosen: the architecture/OpenWrt default this binary would
// use, and an explicit override (agent.yml Drivers.Frp.ReadyTimeoutSec, D4).
func TestNewUsesTheArchitectureDefaultAndTheOverride(t *testing.T) {
	want := driver.DefaultReadyTimeout(runtime.GOARCH, false)
	if got := New(Options{}).ReadyTimeout(); got != want {
		t.Errorf("New(Options{}).ReadyTimeout() = %s, want the %s default %s", got, runtime.GOARCH, want)
	}
	// OpenWrt always widens the default, whatever this binary was built for.
	wantOpenWrt := driver.DefaultReadyTimeout(runtime.GOARCH, true)
	if got := New(Options{OpenWrt: true}).ReadyTimeout(); got != wantOpenWrt {
		t.Errorf("New(Options{OpenWrt: true}).ReadyTimeout() = %s, want the OpenWrt default %s", got, wantOpenWrt)
	}
	if got := New(Options{ReadyTimeout: 5 * time.Second}).ReadyTimeout(); got != 5*time.Second {
		t.Errorf("explicit override = %s, want 5s", got)
	}
	// An explicit override wins over OpenWrt too.
	if got := New(Options{OpenWrt: true, ReadyTimeout: 5 * time.Second}).ReadyTimeout(); got != 5*time.Second {
		t.Errorf("explicit override on OpenWrt = %s, want 5s", got)
	}
	// A non-positive override means "use the default", never "no wait".
	for _, bad := range []time.Duration{0, -time.Second} {
		if got := New(Options{ReadyTimeout: bad}).ReadyTimeout(); got != want {
			t.Errorf("New(Options{ReadyTimeout: %s}).ReadyTimeout() = %s, want the default %s", bad, got, want)
		}
	}
}
