package driver

import "time"

// DefaultReadyTimeout is the readiness limit shared by the drivers that
// supervise a kernel process and wait for it to answer: frp (frps/frpc
// management API, D4) and gost (its REST API, F6). The v11 T2 run on QEMU
// MIPS/ARM measured the old hard-coded limits (15s in frp, 10s in gost) being
// hit on router CPUs, so both drivers now size the wait the same way.
//
// A 64-bit x86/ARM server starts its kernel in a couple of seconds, so 15s is
// generous there. Everything else gets 60s:
//
//   - the 32-bit router targets (mips/mipsle, arm, 386) and the other 64-bit
//     targets (riscv64, ...);
//   - any architecture on OpenWrt. Router CPUs are far weaker than their
//     GOARCH suggests -- an arm64 MT7981 (Cortex-A53) is not an arm64 server,
//     and the T2 run still measured 3 readiness timeouts on simulated arm64.
//
// openWrt is the platform.Detect() OpenWrt fact of the machine the agent runs
// on. A non-positive agent.yml override never reaches this function; the
// drivers call it only when they have no explicit ReadyTimeout.
func DefaultReadyTimeout(goarch string, openWrt bool) time.Duration {
	switch goarch {
	case "amd64", "arm64":
		if !openWrt {
			return 15 * time.Second
		}
	}
	return 60 * time.Second
}
