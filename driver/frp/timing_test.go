package frp

import (
	"runtime"
	"testing"
	"time"
)

// TestDefaultReadyTimeoutIsPerArchitecture covers D4: the readiness limit is
// 15s on the fast 64-bit targets and 60s everywhere else. The v11 D4 run
// measured a 15s limit being hit repeatedly on MIPS/ARM routers (QEMU TCG),
// where frps needs much longer to start and open its admin API.
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
		if got := DefaultReadyTimeout(tc.goarch); got != tc.want {
			t.Errorf("DefaultReadyTimeout(%q) = %s, want %s", tc.goarch, got, tc.want)
		}
	}
}

// TestNewUsesTheArchitectureDefaultAndTheOverride covers the two ways the
// readiness limit is chosen: the architecture this binary was built for, and
// an explicit override (agent.yml Drivers.Frp.ReadyTimeoutSec, D4).
func TestNewUsesTheArchitectureDefaultAndTheOverride(t *testing.T) {
	want := DefaultReadyTimeout(runtime.GOARCH)
	if got := New(Options{}).ReadyTimeout(); got != want {
		t.Errorf("New(Options{}).ReadyTimeout() = %s, want the %s default %s", got, runtime.GOARCH, want)
	}
	if got := New(Options{ReadyTimeout: 5 * time.Second}).ReadyTimeout(); got != 5*time.Second {
		t.Errorf("explicit override = %s, want 5s", got)
	}
	// A non-positive override means "use the default", never "no wait".
	for _, bad := range []time.Duration{0, -time.Second} {
		if got := New(Options{ReadyTimeout: bad}).ReadyTimeout(); got != want {
			t.Errorf("New(Options{ReadyTimeout: %s}).ReadyTimeout() = %s, want the default %s", bad, got, want)
		}
	}
}
