package node

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/core"
)

// A route.json written for XrayR matches inbounds by "<Type>_<IP>_<Port>".
// The same rule must keep working: W1nCray maps it to the node listening on
// that port, so traffic is really routed (here: blocked) by it.
func TestE2EXrayRLegacyInboundTag(t *testing.T) {
	tgt := target(t)
	for _, tc := range []struct {
		name    string
		tagFor  func(port int, host string) string
		blocked bool
	}{
		{"xrayr tag of this node's port", func(p int, _ string) string { return fmt.Sprintf("V2ray_0.0.0.0_%d", p) }, true},
		{"xrayr tag of another port", func(p int, _ string) string { return fmt.Sprintf("V2ray_0.0.0.0_%d", p+1) }, false},
		{"w1ncray node tag", func(_ int, host string) string { return "node1@" + host }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			port := freePort(t, "tcp")
			fp := newFakePanel(t, vmessNode(port, "[]"), panelUsers(0, 0))
			u, err := url.Parse(fp.srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			route := filepath.Join(t.TempDir(), "route.json")
			rule := fmt.Sprintf(`{"rules":[{"type":"field","inboundTag":["%s"],"outboundTag":"w1ncray-block"}]}`, tc.tagFor(port, u.Host))
			if err := os.WriteFile(route, []byte(rule), 0o600); err != nil {
				t.Fatal(err)
			}
			startServerWith(t, fp, nil, func(o *core.Options) { o.RouteConfigPath = route })

			c := startClient(t, protoCases[0].client(port, uuid1))
			_, err = c.get(tgt.URL+"/bytes?n=100", 4*time.Second)
			if tc.blocked && err == nil {
				t.Fatal("the rule did not take effect")
			}
			if !tc.blocked && err != nil {
				t.Fatalf("a rule for another port must not affect this node: %v", err)
			}
		})
	}
}
