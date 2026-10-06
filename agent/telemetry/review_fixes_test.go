package telemetry

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
)

// Components must serialise "instances" as an array for every item, never null:
// the panel stores the document and the page iterates it.
func TestComponentsInstancesIsNeverNull(t *testing.T) {
	c := New(Options{AgentVersion: "t"})
	raw, err := json.Marshal(c.Components(context.Background()))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"instances":null`) {
		t.Fatalf("instances serialised as null: %s", raw)
	}
}

// Loopback and link-local addresses are identical on every host: they must not
// be reported as the machine's private IPs.
func TestPrivateIPsExcludeLoopbackAndLinkLocal(t *testing.T) {
	hi := New(Options{}).HostInfo(context.Background())
	for _, s := range hi.IPs.Private {
		ip := net.ParseIP(s)
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || !ip.IsPrivate() {
			t.Errorf("unexpected address in private IPs: %s", s)
		}
	}
}

func TestClassifyIPsSplitsPrivateAndPublic(t *testing.T) {
	mk := func(s string) net.Addr { return &net.IPNet{IP: net.ParseIP(s), Mask: net.CIDRMask(24, 32)} }
	got := classifyIPs([]net.Addr{
		mk("127.0.0.1"), mk("169.254.1.1"), mk("fe80::1"), mk("10.0.0.5"), mk("100.64.1.2"),
		mk("203.0.113.10"), mk("2001:db8::1"), mk("fd00::1"), mk("203.0.113.10"),
	})
	if strings.Join(got.Private, ",") != "10.0.0.5,100.64.1.2,fd00::1" {
		t.Fatalf("private = %v", got.Private)
	}
	if strings.Join(got.Public, ",") != "2001:db8::1,203.0.113.10" {
		t.Fatalf("public = %v", got.Public)
	}
}
