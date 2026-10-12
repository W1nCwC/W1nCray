package certreload

import (
	"reflect"
	"testing"

	"github.com/W1nCwC/W1nCray/agent/spec"
)

// certInstance builds an enabled tunnel instance that references certFile and
// keyFile (either may be empty).
func certInstance(id, certFile, keyFile string) spec.Instance {
	return spec.Instance{
		ID: id, Enabled: true, Engine: spec.EngineGost, Kind: spec.KindTunnelExit,
		Tunnel: &spec.Tunnel{
			Type:   "wss",
			Listen: "0.0.0.0:8443",
			Cert:   &spec.Cert{Mode: "file", CertFile: certFile, KeyFile: keyFile},
		},
	}
}

const (
	certPath = "/etc/w1ncray/xray/cert.pem"
	keyPath  = "/etc/w1ncray/xray/key.pem"
)

// TestPathsListsTheCertificatePair pins what a spec references: the tunnel
// certificate pair, deduplicated, and nothing at all without a file-mode cert.
func TestPathsListsTheCertificatePair(t *testing.T) {
	if got := Paths(certInstance("a", certPath, keyPath)); !reflect.DeepEqual(got, []string{certPath, keyPath}) {
		t.Errorf("Paths = %v", got)
	}
	if got := Paths(certInstance("a", certPath, certPath)); !reflect.DeepEqual(got, []string{certPath}) {
		t.Errorf("Paths with one file named twice = %v", got)
	}
	// A forward has no tunnel, and a self/panel certificate has no files: no
	// managed file change may restart them.
	plain := spec.Instance{ID: "f", Enabled: true, Engine: spec.EngineGost, Kind: spec.KindForward}
	if got := Paths(plain); got != nil {
		t.Errorf("Paths of a forward = %v", got)
	}
	self := certInstance("s", "", "")
	self.Tunnel.Cert.Mode = "self"
	if got := Paths(self); got != nil {
		t.Errorf("Paths of a self certificate = %v", got)
	}
}

// TestChangedMatchesByExactPath is the core association rule: a changed file
// restarts the enabled instances whose spec names its path, and only those.
func TestChangedMatchesByExactPath(t *testing.T) {
	d := spec.Desired{Instances: []spec.Instance{
		certInstance("exit", certPath, keyPath),          // references both
		certInstance("other", "/etc/ssl/x/cert.pem", ""), // references another file
		{ID: "fwd", Enabled: true, Engine: spec.EngineGost, Kind: spec.KindForward},
	}}

	got := Changed(d, []Ref{{Name: "cert.pem", Path: certPath}})
	if !reflect.DeepEqual(got, []string{"exit"}) {
		t.Errorf("Changed(cert.pem) = %v, want [exit]", got)
	}
	// The key file matches the same instance, once (deduplicated).
	got = Changed(d, []Ref{{Name: "key.pem", Path: keyPath}})
	if !reflect.DeepEqual(got, []string{"exit"}) {
		t.Errorf("Changed(key.pem) = %v, want [exit]", got)
	}
	// A file nobody references restarts nobody: no needless interruption.
	got = Changed(d, []Ref{{Name: "geoip.dat", Path: "/etc/w1ncray/xray/geoip.dat"}})
	if len(got) != 0 {
		t.Errorf("Changed(geoip.dat) = %v, want none", got)
	}
}

// TestChangedMatchesARelativeReference: an engine runs with the configuration
// directory as its working directory, so a spec may name the file by its plain
// name. It has to match, while a path with a directory part is never guessed.
func TestChangedMatchesARelativeReference(t *testing.T) {
	d := spec.Desired{Instances: []spec.Instance{
		certInstance("rel", "cert.pem", ""),
		certInstance("nested", "certs/cert.pem", ""),
	}}
	got := Changed(d, []Ref{{Name: "cert.pem", Path: certPath}})
	if !reflect.DeepEqual(got, []string{"rel"}) {
		t.Errorf("Changed = %v, want [rel] (a nested relative path must not match)", got)
	}
}

// TestChangedMergesEveryChangedFileInOneRound is the throttle rule: one call
// with every file of an apply returns each affected instance exactly once, so
// several files changed together restart an instance once.
func TestChangedMergesEveryChangedFileInOneRound(t *testing.T) {
	d := spec.Desired{Instances: []spec.Instance{
		certInstance("both", certPath, keyPath),
		certInstance("only-cert", certPath, ""),
		certInstance("only-key", "", keyPath),
	}}
	got := Changed(d, []Ref{
		{Name: "cert.pem", Path: certPath},
		{Name: "key.pem", Path: keyPath},
		{Name: "route.json", Path: "/etc/w1ncray/xray/route.json"},
	})
	want := []string{"both", "only-cert", "only-key"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Changed = %v, want %v", got, want)
	}
}

// TestChangedIgnoresDisabledInstances: a disabled instance runs nothing, and
// enabling it applies the desired state (and the new file) anyway.
func TestChangedIgnoresDisabledInstances(t *testing.T) {
	off := certInstance("off", certPath, keyPath)
	off.Enabled = false
	d := spec.Desired{Instances: []spec.Instance{off, certInstance("on", certPath, "")}}
	got := Changed(d, []Ref{{Name: "cert.pem", Path: certPath}})
	if !reflect.DeepEqual(got, []string{"on"}) {
		t.Errorf("Changed = %v, want [on]", got)
	}
}

// TestChangedWithoutChangedFilesIsANoOp: nothing changed, nothing restarts.
func TestChangedWithoutChangedFilesIsANoOp(t *testing.T) {
	d := spec.Desired{Instances: []spec.Instance{certInstance("exit", certPath, keyPath)}}
	if got := Changed(d, nil); got != nil {
		t.Errorf("Changed(nil) = %v", got)
	}
	if got := Changed(spec.Desired{}, []Ref{{Name: "cert.pem", Path: certPath}}); got != nil {
		t.Errorf("Changed on an empty desired state = %v", got)
	}
}
