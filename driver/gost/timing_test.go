package gost

import (
	"runtime"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
)

// TestReadyTimeoutDefaultOverrideAndOpenWrt covers F6's gost half: the
// readiness limit is no longer the hard-coded 10s. It follows the shared
// driver default (15s on amd64/arm64 off OpenWrt, 60s everywhere else,
// including every architecture on OpenWrt) and an explicit override
// (agent.yml Drivers.Gost.ReadyTimeoutSec) replaces it. A non-positive
// override means "use the default", never "no wait".
func TestReadyTimeoutDefaultOverrideAndOpenWrt(t *testing.T) {
	want := driver.DefaultReadyTimeout(runtime.GOARCH, false)
	if got := New(Options{}).ReadyTimeout(); got != want {
		t.Errorf("New(Options{}).ReadyTimeout() = %s, want the %s default %s", got, runtime.GOARCH, want)
	}
	// On OpenWrt the default is always the slow one, whatever this binary was
	// built for: an arm64 router (MT7981) is not an arm64 server.
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
	for _, bad := range []time.Duration{0, -time.Second} {
		if got := New(Options{ReadyTimeout: bad}).ReadyTimeout(); got != want {
			t.Errorf("New(Options{ReadyTimeout: %s}).ReadyTimeout() = %s, want the default %s", bad, got, want)
		}
	}
}

// TestSetDefaultsLeavesTheOtherOptionsAlone guards the shared setDefaults path
// F6 changed: only the readiness limit follows the architecture.
func TestSetDefaultsLeavesTheOtherOptionsAlone(t *testing.T) {
	d := New(Options{})
	if d.opts.LogLevel != "warn" {
		t.Errorf("LogLevel = %q, want warn", d.opts.LogLevel)
	}
	if d.opts.APITimeout != 5*time.Second {
		t.Errorf("APITimeout = %s, want 5s", d.opts.APITimeout)
	}
	if d.opts.MaxListenPorts != defaultMaxListenPorts {
		t.Errorf("MaxListenPorts = %d, want %d", d.opts.MaxListenPorts, defaultMaxListenPorts)
	}
}
