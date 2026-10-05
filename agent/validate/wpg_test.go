package validate

import (
	"strings"
	"testing"

	"github.com/W1nCwC/W1nCray/agent/spec"
)

// TestSecretCharsetIsEngineIntersection pins the secret alphabet to what every
// engine accepts. Engine rules at the time of writing:
//
//	xray  [A-Za-z0-9+/=_.:@-]   rejects '~'
//	frp   [A-Za-z0-9._~+/=-]    rejects ':' and '@'
//	gost  printable ASCII       rejects space, control and non-ASCII
//	realm length only
//
// so the common alphabet is letters, digits and - _ . + / =.
func TestSecretCharsetIsEngineIntersection(t *testing.T) {
	base := "0123456789abcdef"
	rejected := []struct{ name, ch string }{
		{"tilde (xray)", "~"},
		{"colon (frp)", ":"},
		{"at (frp)", "@"},
		{"space (gost)", " "},
		{"tab", "\t"},
		{"newline", "\n"},
		{"DEL", "\x7f"},
		{"non-ASCII", "é"},
		{"double quote", `"`},
		{"single quote", "'"},
		{"backslash", `\`},
		{"brace", "{"},
		{"dollar", "$"},
		{"hash", "#"},
		{"percent", "%"},
	}
	for _, kind := range []struct {
		name string
		base func() spec.Instance
	}{{"entry", entry}, {"exit", exit}, {"portal", portal}, {"bridge", bridge}} {
		for _, c := range rejected {
			t.Run(kind.name+"/"+c.name, func(t *testing.T) {
				in := kind.base()
				in.Secret = base + c.ch + "tail"
				errs := Desired(desired(in), policy(), opts())
				if !find(errs, "secret", "16-256") {
					t.Fatalf("secret with %s must be rejected, got:%s", c.name, dump(errs))
				}
			})
		}
	}
	// The message names the allowed characters and never echoes the secret.
	in := entry()
	in.Secret = base + "~tail"
	errs := Desired(desired(in), policy(), opts())
	if !find(errs, "secret", "[A-Za-z0-9_.+/=-]") {
		t.Fatalf("message must list the allowed characters, got:%s", dump(errs))
	}
	if strings.Contains(dump(errs), "tail") {
		t.Fatalf("secret echoed: %s", dump(errs))
	}
	// Every legal character, at the length limits.
	for _, s := range []string{
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz", "0123456789012345",
		"a-b_c.d+e/f=g-h_i.j+k/l=m", strings.Repeat("a", 16), strings.Repeat("A-_.+/=", 37)[:256],
	} {
		in := entry()
		in.Secret = s
		if errs := Desired(desired(in), policy(), opts()); len(errs) != 0 {
			t.Errorf("secret %q must be valid:%s", s, dump(errs))
		}
	}
	for _, n := range []int{15, 257} {
		in := entry()
		in.Secret = strings.Repeat("a", n)
		if errs := Desired(desired(in), policy(), opts()); !find(errs, "secret", "16-256") {
			t.Errorf("length %d must be rejected, got:%s", n, dump(errs))
		}
	}
}

// TestClientTrustAnchor covers tunnel.cert on the client side kinds: only
// mode "file" with cert_file (the trust anchor) and no key_file.
func TestClientTrustAnchor(t *testing.T) {
	for _, k := range []struct {
		name string
		base func() spec.Instance
	}{{"entry", entry}, {"bridge", bridge}} {
		t.Run(k.name+"/trust anchor ok", func(t *testing.T) {
			in := k.base()
			in.Tunnel.Cert = &spec.Cert{Mode: "file", CertFile: "/etc/w1ncray/ca.pem"}
			if errs := Desired(desired(in), policy(), opts()); len(errs) != 0 {
				t.Fatalf("trust anchor must be accepted:%s", dump(errs))
			}
		})
		bad := []struct {
			name   string
			c      spec.Cert
			field  string
			substr string
		}{
			{"key_file", spec.Cert{Mode: "file", CertFile: "/etc/ca.pem", KeyFile: "/etc/ca.key"}, "tunnel.cert.key_file", "not used"},
			{"mode self", spec.Cert{Mode: "self"}, "tunnel.cert.mode", "only supports mode"},
			{"mode panel", spec.Cert{Mode: "panel"}, "tunnel.cert.mode", "only supports mode"},
			{"unknown mode", spec.Cert{Mode: "magic"}, "tunnel.cert.mode", "unknown mode"},
			{"no cert_file", spec.Cert{Mode: "file"}, "tunnel.cert.cert_file", "absolute path"},
			{"relative", spec.Cert{Mode: "file", CertFile: "ca.pem"}, "tunnel.cert.cert_file", "absolute path"},
			{"traversal", spec.Cert{Mode: "file", CertFile: "/etc/../shadow"}, "tunnel.cert.cert_file", "absolute path"},
			{"injection", spec.Cert{Mode: "file", CertFile: "/a.pem\n"}, "tunnel.cert.cert_file", "absolute path"},
			{"space", spec.Cert{Mode: "file", CertFile: "/a b.pem"}, "tunnel.cert.cert_file", "absolute path"},
		}
		for _, b := range bad {
			t.Run(k.name+"/"+b.name, func(t *testing.T) {
				in := k.base()
				c := b.c
				in.Tunnel.Cert = &c
				errs := Desired(desired(in), policy(), opts())
				if !find(errs, b.field, b.substr) {
					t.Fatalf("want %s containing %q, got:%s", b.field, b.substr, dump(errs))
				}
			})
		}
	}
}

// TestServerCertRulesUnchanged: exit and portal still need both files in file
// mode, and "self" takes no files.
func TestServerCertRulesUnchanged(t *testing.T) {
	for _, k := range []struct {
		name string
		base func() spec.Instance
	}{{"exit", exit}, {"portal", portal}} {
		t.Run(k.name, func(t *testing.T) {
			in := k.base()
			in.Tunnel.Cert = &spec.Cert{Mode: "file", CertFile: "/etc/c.pem", KeyFile: "/etc/k.pem"}
			if errs := Desired(desired(in), policy(), opts()); len(errs) != 0 {
				t.Fatalf("server file cert must stay valid:%s", dump(errs))
			}
			in.Tunnel.Cert = &spec.Cert{Mode: "file", CertFile: "/etc/c.pem"}
			if errs := Desired(desired(in), policy(), opts()); !find(errs, "tunnel.cert.key_file", "absolute path") {
				t.Fatalf("server file cert without key_file must be rejected, got:%s", dump(errs))
			}
			in.Tunnel.Cert = &spec.Cert{Mode: "self", CertFile: "/a"}
			if errs := Desired(desired(in), policy(), opts()); !find(errs, "tunnel.cert", "only used with mode") {
				t.Fatalf("got:%s", dump(errs))
			}
			in.Tunnel.Cert = &spec.Cert{Mode: "self"}
			if errs := Desired(desired(in), policy(), opts()); len(errs) != 0 {
				t.Fatalf("self must stay valid:%s", dump(errs))
			}
		})
	}
}
