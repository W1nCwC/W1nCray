package driver

import (
	"testing"
	"time"
)

// TestDefaultReadyTimeout pins the shared table (F6): amd64/arm64 off OpenWrt
// take the 15s fast path, everything else takes 60s -- including every
// architecture on OpenWrt, where a router CPU is much weaker than its GOARCH
// suggests (an arm64 MT7981 is not an arm64 server). T2 measured the 15s limit
// still timing out on simulated arm64.
func TestDefaultReadyTimeout(t *testing.T) {
	for _, tc := range []struct {
		goarch  string
		openWrt bool
		want    time.Duration
	}{
		{"amd64", false, 15 * time.Second},
		{"arm64", false, 15 * time.Second},

		// OpenWrt: any architecture is a router, so no fast path.
		{"amd64", true, 60 * time.Second},
		{"arm64", true, 60 * time.Second},

		// Non-OpenWrt slow targets.
		{"386", false, 60 * time.Second},
		{"arm", false, 60 * time.Second},
		{"mips", false, 60 * time.Second},
		{"mipsle", false, 60 * time.Second},
		{"mips64", false, 60 * time.Second},
		{"mips64le", false, 60 * time.Second},
		{"riscv64", false, 60 * time.Second},

		// OpenWrt slow targets.
		{"386", true, 60 * time.Second},
		{"arm", true, 60 * time.Second},
		{"mipsle", true, 60 * time.Second},
		{"riscv64", true, 60 * time.Second},

		// An unknown/future GOARCH must not silently take the fast path.
		{"loong64", false, 60 * time.Second},
		{"loong64", true, 60 * time.Second},
	} {
		if got := DefaultReadyTimeout(tc.goarch, tc.openWrt); got != tc.want {
			t.Errorf("DefaultReadyTimeout(%q, openWrt=%v) = %s, want %s", tc.goarch, tc.openWrt, got, tc.want)
		}
	}
}
