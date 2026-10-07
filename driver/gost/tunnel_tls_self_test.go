package gost

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/spec"
	"github.com/W1nCwC/W1nCray/agent/tlsself"
)

const selfSNI = "tun.example.net"

func tlsSelfExit() spec.Instance {
	return spec.Instance{
		ID: "self-ex", Enabled: true, Engine: spec.EngineGost, Kind: spec.KindTunnelExit,
		Network: []string{"tcp"},
		Tunnel:  &spec.Tunnel{Type: "tls", Listen: "0.0.0.0:4443", SNI: selfSNI, Security: "tls_self"},
		Targets: []spec.Target{{Host: "10.0.0.7", Ports: "5201"}},
		Secret:  testSecret,
	}
}

func tlsSelfEntry() spec.Instance {
	return spec.Instance{
		ID: "self-en", Enabled: true, Engine: spec.EngineGost, Kind: spec.KindTunnelEntry,
		Listen:  &spec.Listen{Addr: "127.0.0.1", Ports: "7000"},
		Network: []string{"tcp"},
		Tunnel:  &spec.Tunnel{Type: "tls", Server: "exit.example.com:4443", SNI: selfSNI, Security: "tls_self"},
		Secret:  testSecret,
	}
}

// TestRenderTLSSelfExit covers the accepting side: the derived certificate and
// key travel in the artifact (the fragment references them by their plain file
// names, which gost resolves against its working directory, the state
// directory) and the listener serves them.
func TestRenderTLSSelfExit(t *testing.T) {
	in := tlsSelfExit()
	d := New(Options{})
	if err := d.Validate(in); err != nil {
		t.Fatalf("validate: %v", err)
	}
	a, err := d.Render(in)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, _, err := tlsself.SelfCert(testSecret, selfSNI)
	if err != nil {
		t.Fatal(err)
	}
	certName, keyName := "tls_self_"+in.ID+".crt", "tls_self_"+in.ID+".key"
	if got := string(a.Files[certName]); got != certPEM {
		t.Errorf("%s is not the derived certificate:\n%s", certName, got)
	}
	if got := string(a.Files[keyName]); got != keyPEM {
		t.Errorf("%s is not the derived key", keyName)
	}
	if len(a.Files) != 3 {
		t.Errorf("artifact files = %v, want fragment + cert + key", keysOf(a.Files))
	}
	f := frag(t, in)
	if len(f.Services) != 1 {
		t.Fatalf("services = %+v", f.Services)
	}
	l := f.Services[0].Listener
	if l.TLS == nil || l.TLS.CertFile != certName || l.TLS.KeyFile != keyName {
		t.Errorf("listener tls = %+v, want certFile %s / keyFile %s", l.TLS, certName, keyName)
	}
	// The rendering stays a pure function (and the hash covers the PEMs).
	again, err := d.Render(in)
	if err != nil {
		t.Fatal(err)
	}
	if again.Hash != a.Hash {
		t.Error("the tls_self artifact is not deterministic")
	}
}

// TestRenderTLSSelfEntry covers the dialing side: it only needs the derived
// certificate as its trust anchor, verifies the name in it (secure: true) and
// sends the certificate's name as serverName.
func TestRenderTLSSelfEntry(t *testing.T) {
	in := tlsSelfEntry()
	d := New(Options{})
	if err := d.Validate(in); err != nil {
		t.Fatalf("validate: %v", err)
	}
	a, err := d.Render(in)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, _, _, err := tlsself.SelfCert(testSecret, selfSNI)
	if err != nil {
		t.Fatal(err)
	}
	certName := "tls_self_" + in.ID + ".crt"
	if string(a.Files[certName]) != certPEM {
		t.Errorf("%s is not the derived certificate", certName)
	}
	if _, ok := a.Files["tls_self_"+in.ID+".key"]; ok {
		t.Error("the dialing side must not carry the private key")
	}
	dl := frag(t, in).Chains[0].Hops[0].Nodes[0].Dialer
	if dl.TLS == nil {
		t.Fatal("the dialer has no tls section")
	}
	if !dl.TLS.Secure {
		t.Error("tls_self must verify the certificate (secure: true)")
	}
	if dl.TLS.CAFile != certName {
		t.Errorf("caFile = %q, want %q (the certificate is its own CA)", dl.TLS.CAFile, certName)
	}
	if dl.TLS.ServerName != selfSNI {
		t.Errorf("serverName = %q, want %q", dl.TLS.ServerName, selfSNI)
	}

	// No SNI: the certificate carries the shared default name, and that is
	// what the dialing side must send.
	noSNI := tlsSelfEntry()
	noSNI.Tunnel.SNI = ""
	a, err = d.Render(noSNI)
	if err != nil {
		t.Fatal(err)
	}
	dl = frag(t, noSNI).Chains[0].Hops[0].Nodes[0].Dialer
	if dl.TLS.ServerName != tlsself.DefaultName {
		t.Errorf("serverName = %q, want %q", dl.TLS.ServerName, tlsself.DefaultName)
	}
	if string(a.Files["tls_self_"+noSNI.ID+".crt"]) != mustCert(t, testSecret, "") {
		t.Error("the certificate must be derived from the default name")
	}
}

func mustCert(t *testing.T, secret, sni string) string {
	t.Helper()
	certPEM, _, _, err := tlsself.SelfCert(secret, sni)
	if err != nil {
		t.Fatal(err)
	}
	return certPEM
}

func keysOf(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestWriteArtifactFiles covers the file half of Apply: the certificate and key
// land in the state directory (0600, atomically), and a name that could escape
// it is refused.
func TestWriteArtifactFiles(t *testing.T) {
	dir := t.TempDir()
	rt := driver.Runtime{StateDir: dir}
	in := tlsSelfExit()
	a, err := New(Options{}).Render(in)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeArtifactFiles(rt, []driver.Rendered{{Instance: in, Artifact: a}}); err != nil {
		t.Fatalf("writeArtifactFiles: %v", err)
	}
	for _, name := range []string{"tls_self_" + in.ID + ".crt", "tls_self_" + in.ID + ".key"} {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if string(got) != string(a.Files[name]) {
			t.Errorf("%s does not hold the artifact content", name)
		}
		if fi, err := os.Stat(filepath.Join(dir, name)); err == nil && runtime.GOOS != "windows" {
			if perm := fi.Mode().Perm(); perm != 0o600 {
				t.Errorf("%s mode = %04o, want 0600", name, perm)
			}
		}
	}
	if _, err := os.Stat(filepath.Join(dir, fragmentFile)); !os.IsNotExist(err) {
		t.Error("the fragment must not be written to disk")
	}
	// A name with a separator (or "..") is refused instead of being joined.
	for _, bad := range []string{"../evil.pem", "sub/evil.pem", "..", ""} {
		bad := bad
		a2 := a
		a2.Files = map[string][]byte{fragmentFile: a.Files[fragmentFile], bad: []byte("x")}
		if err := writeArtifactFiles(rt, []driver.Rendered{{Instance: in, Artifact: a2}}); err == nil {
			t.Errorf("artifact file name %q was accepted", bad)
		}
	}
}

// TestApplyWritesTheTLSSelfFiles pins the wiring: Apply writes the artifact
// files before it touches the process, so the certificate exists by the time
// gost is asked to serve it. The runtime has no supervisor, so Apply fails
// right after that — which is what makes this a unit test.
func TestApplyWritesTheTLSSelfFiles(t *testing.T) {
	dir := t.TempDir()
	in := tlsSelfExit()
	d := New(Options{})
	a, err := d.Render(in)
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.Apply(context.Background(), driver.Runtime{StateDir: dir}, []driver.Rendered{{Instance: in, Artifact: a}})
	if err == nil {
		t.Fatal("Apply without a supervisor succeeded")
	}
	for _, name := range []string{"tls_self_" + in.ID + ".crt", "tls_self_" + in.ID + ".key"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s was not written before the process step: %v", name, err)
		}
	}
}

// TestValidateTLSSelf covers what the gost driver accepts and refuses.
func TestValidateTLSSelf(t *testing.T) {
	d := New(Options{})
	for _, ty := range []string{"tls", "wss", "grpc"} {
		in := tlsSelfExit()
		in.Tunnel.Type, in.Tunnel.Listen = ty, "0.0.0.0:4443"
		if err := d.Validate(in); err != nil {
			t.Errorf("%s/tls_self: %v", ty, err)
		}
	}
	// A carrier the engine cannot wrap in TLS.
	for _, ty := range []string{"tcp", "ws"} {
		in := tlsSelfExit()
		in.Tunnel.Type = ty
		if err := d.Validate(in); err == nil || !strings.Contains(err.Error(), "TLS carrier") {
			t.Errorf("%s/tls_self = %v, want the TLS-carrier refusal", ty, err)
		}
	}
	// The certificate comes from the secret.
	noSecret := tlsSelfExit()
	noSecret.Secret = ""
	if err := d.Validate(noSecret); err == nil {
		t.Error("tls_self without a secret was accepted")
	}
	// pin_sha256 is derived by the engines that pin; gost never pins.
	withPin := tlsSelfExit()
	withPin.Tunnel.PinSHA256 = strings.Repeat("ab", 32)
	if err := d.Validate(withPin); err == nil || !strings.Contains(err.Error(), "pin_sha256") {
		t.Errorf("tls_self with a pin = %v, want the pin refusal", err)
	}
	// tunnel.cert contradicts the derivation.
	withCert := tlsSelfExit()
	withCert.Tunnel.Cert = &spec.Cert{Mode: "file", CertFile: "/etc/w1n/c.pem", KeyFile: "/etc/w1n/k.pem"}
	if err := d.Validate(withCert); err == nil || !strings.Contains(err.Error(), "tunnel.cert") {
		t.Errorf("tls_self with a cert = %v, want the cert refusal", err)
	}
	// The fragment must not leak the secret into the PEM files, and it stays
	// valid JSON.
	a, err := d.Render(tlsSelfExit())
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range a.Files {
		if strings.Contains(string(data), testSecret) && name != fragmentFile {
			t.Errorf("%s contains the secret", name)
		}
	}
	if !json.Valid(a.Files[fragmentFile]) {
		t.Error("the fragment is not valid JSON")
	}
}

// TestRenderTLSSelfGRPCAuthority: grpc-go requires the ClientConn authority to
// match the TLS server name, so a gRPC tls_self entry dials with host = the
// certificate name (test VPS: "authority ... don't match" before this).
func TestRenderTLSSelfGRPCAuthority(t *testing.T) {
	in := tlsSelfEntry()
	in.Tunnel.Type = "grpc"
	in.Tunnel.SNI = ""
	d := New(Options{})
	if err := d.Validate(in); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if _, err := d.Render(in); err != nil {
		t.Fatal(err)
	}
	dl := frag(t, in).Chains[0].Hops[0].Nodes[0].Dialer
	if dl.Metadata["host"] != tlsself.DefaultName {
		t.Errorf("grpc host = %q, want %q", dl.Metadata["host"], tlsself.DefaultName)
	}
}
