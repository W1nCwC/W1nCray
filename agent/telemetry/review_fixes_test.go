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
