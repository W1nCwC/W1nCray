package frp

import (
	"strings"
	"testing"

	"github.com/W1nCwC/W1nCray/agent/spec"
)

const (
	tokA = "tok-AAAAAAAAAAAAAAAAAAAAAAAA"
	tokB = "tok-BBBBBBBBBBBBBBBBBBBBBBBB"
)

func portalInst() spec.Instance {
	return spec.Instance{
		ID: "web", Enabled: true, Engine: spec.EngineFrp, Kind: spec.KindReversePortal,
		Network: []string{"tcp", "udp"},
		Listen:  &spec.Listen{Addr: "0.0.0.0", Ports: "20000-20009"},
		Tunnel: &spec.Tunnel{
			Type: "tcp", Listen: "0.0.0.0:7000", Security: "tls",
			Cert: &spec.Cert{Mode: "file", CertFile: "/etc/w1nc/frp.crt", KeyFile: "/etc/w1nc/frp.key"},
		},
		Secret: tokA,
	}
}

func bridgeInst() spec.Instance {
	return spec.Instance{
		ID: "web", Enabled: true, Engine: spec.EngineFrp, Kind: spec.KindReverseBridge,
		Network: []string{"tcp", "udp"},
		Listen:  &spec.Listen{Ports: "20000-20009"},
		Targets: []spec.Target{{Host: "127.0.0.1", Ports: "8000-8009"}},
		Tunnel: &spec.Tunnel{
			Type: "tcp", Server: "portal.example.com:7000", Security: "tls", SNI: "portal.example.com",
			Cert: &spec.Cert{Mode: "file", CertFile: "/etc/w1nc/portal-ca.pem"},
		},
		ProxyProtocolOut: 0,
		Secret:           tokA,
	}
}

func mustCompile(t *testing.T, in spec.Instance) *unit {
	t.Helper()
	u, err := compile(in)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return u
}

func mustRejectWith(t *testing.T, in spec.Instance, substr string) {
	t.Helper()
	err := New(Options{}).Validate(in)
	if err == nil {
		t.Fatalf("Validate accepted the instance, want error containing %q", substr)
	}
	if !strings.Contains(err.Error(), substr) {
		t.Fatalf("error %q does not contain %q", err, substr)
	}
	if strings.Contains(err.Error(), in.Secret) && in.Secret != "" {
		t.Fatalf("error leaks the secret: %q", err)
	}
}
