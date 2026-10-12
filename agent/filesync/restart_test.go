package filesync

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/W1nCwC/W1nCray/agent/spec"
)

// stubRestarter records the restart rounds and can fail them.
type stubRestarter struct {
	mu    sync.Mutex
	round [][]string
	err   error
}

func (s *stubRestarter) RestartInstances(_ context.Context, ids []string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.round = append(s.round, append([]string(nil), ids...))
	if s.err != nil {
		return nil, s.err
	}
	return append([]string(nil), ids...), nil
}

func (s *stubRestarter) rounds() [][]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][]string(nil), s.round...)
}

// desiredSource is a Source that also reports the whole desired state, which is
// what lets the applier tell which instances reference a changed file.
type desiredSource struct {
	files []spec.FileRef
	d     spec.Desired
}

func (s desiredSource) DesiredFiles() []spec.FileRef { return s.files }
func (s desiredSource) Desired() spec.Desired        { return s.d }

// tunnelExit is an enabled tunnel exit that references certFile and keyFile.
func tunnelExit(id, certFile, keyFile string) spec.Instance {
	return spec.Instance{
		ID: id, Enabled: true, Engine: spec.EngineGost, Kind: spec.KindTunnelExit,
		Tunnel: &spec.Tunnel{
			Type:   "wss",
			Listen: "0.0.0.0:8443",
			Cert:   &spec.Cert{Mode: "file", CertFile: certFile, KeyFile: keyFile},
		},
	}
}

// TestApplyRestartsTheInstancesThatReferenceTheChangedFile is the association
// end to end: the file an instance's spec names is replaced, and exactly that
// instance is restarted (through the reconciler), once.
func TestApplyRestartsTheInstancesThatReferenceTheChangedFile(t *testing.T) {
	r := newRig(t)
	r.write(NameRoute, []byte(`{"rules":[]}`))
	content := []byte(`{"rules":[{"type":"field","domain":["example.com"]}]}`)
	ref := r.ref(NameRoute, content)
	routePath := filepath.Join(r.config, NameRoute)

	restart := &stubRestarter{}
	r.applier.SetRestarter(restart)
	r.applier.SetSource(desiredSource{
		files: []spec.FileRef{ref},
		d: spec.Desired{Instances: []spec.Instance{
			tunnelExit("exit", routePath, ""),
			tunnelExit("other", filepath.Join(r.config, "other.pem"), ""),
		}},
	})

	res, err := r.applier.Apply(context.Background(), []spec.FileRef{ref})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Status != StatusDone {
		t.Fatalf("status = %q (%v)", res.Status, res.Errors)
	}
	if res.Restart != RestartRestarted {
		t.Fatalf("restart = %q (failures %v)", res.Restart, res.RestartFailures)
	}
	if !reflect.DeepEqual(res.Restarted, []string{"exit"}) {
		t.Errorf("restarted = %v, want [exit]", res.Restarted)
	}
	rounds := restart.rounds()
	if len(rounds) != 1 || !reflect.DeepEqual(rounds[0], []string{"exit"}) {
		t.Errorf("restart rounds = %v, want one round with [exit]", rounds)
	}
	if got := r.read(NameRoute); got != string(content) {
		t.Errorf("the file was not replaced: %q", got)
	}
}

// TestApplyRestartMergesSeveralChangedFiles is the throttle rule end to end:
// the files of one apply are one restart round, and an instance that
// references two of them is named once.
func TestApplyRestartMergesSeveralChangedFiles(t *testing.T) {
	r := newRig(t)
	r.write(NameRoute, []byte(`{"rules":[]}`))
	r.write(NameDNS, []byte(`{"servers":[]}`))
	routeRef := r.ref(NameRoute, []byte(`{"rules":[{"type":"field"}]}`))
	dnsRef := r.ref(NameDNS, []byte(`{"servers":["1.1.1.1"]}`))
	routePath := filepath.Join(r.config, NameRoute)
	dnsPath := filepath.Join(r.config, NameDNS)

	restart := &stubRestarter{}
	r.applier.SetRestarter(restart)
	r.applier.SetSource(desiredSource{
		files: []spec.FileRef{routeRef, dnsRef},
		d: spec.Desired{Instances: []spec.Instance{
			tunnelExit("both", routePath, dnsPath),
			tunnelExit("route-only", routePath, ""),
			tunnelExit("unrelated", filepath.Join(r.config, "x.pem"), ""),
		}},
	})

	res, err := r.applier.Apply(context.Background(), []spec.FileRef{routeRef, dnsRef})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Restart != RestartRestarted {
		t.Fatalf("restart = %q", res.Restart)
	}
	if !reflect.DeepEqual(res.Restarted, []string{"both", "route-only"}) {
		t.Errorf("restarted = %v", res.Restarted)
	}
	rounds := restart.rounds()
	if len(rounds) != 1 {
		t.Fatalf("rounds = %v, want exactly one", rounds)
	}
	if !reflect.DeepEqual(rounds[0], []string{"both", "route-only"}) {
		t.Errorf("round = %v, want [both route-only] (deduplicated, sorted)", rounds[0])
	}
}

// TestApplyDoesNotRestartForAFileNobodyReferences: a replaced file no instance
// references must not interrupt anything.
func TestApplyDoesNotRestartForAFileNobodyReferences(t *testing.T) {
	r := newRig(t)
	r.write(NameRoute, []byte(`{"rules":[]}`))
	ref := r.ref(NameRoute, []byte(`{"rules":[{"type":"field"}]}`))

	restart := &stubRestarter{}
	r.applier.SetRestarter(restart)
	r.applier.SetSource(desiredSource{
		files: []spec.FileRef{ref},
		d: spec.Desired{Instances: []spec.Instance{
			tunnelExit("exit", filepath.Join(r.config, "cert.pem"), ""),
		}},
	})

	res, err := r.applier.Apply(context.Background(), []spec.FileRef{ref})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Restart != RestartNotNeeded {
		t.Errorf("restart = %q, want %q", res.Restart, RestartNotNeeded)
	}
	if len(restart.rounds()) != 0 {
		t.Errorf("the restarter was called for an unreferenced file: %v", restart.rounds())
	}
}

// TestApplyAlreadyCurrentDoesNotRestart: nothing was replaced, so nothing is
// restarted (a repeated files_apply must not interrupt a healthy instance).
func TestApplyAlreadyCurrentDoesNotRestart(t *testing.T) {
	r := newRig(t)
	content := []byte(`{"rules":[{"type":"field"}]}`)
	r.write(NameRoute, content)
	ref := r.ref(NameRoute, content)

	restart := &stubRestarter{}
	r.applier.SetRestarter(restart)
	r.applier.SetSource(desiredSource{
		files: []spec.FileRef{ref},
		d: spec.Desired{Instances: []spec.Instance{
			tunnelExit("exit", filepath.Join(r.config, NameRoute), ""),
		}},
	})

	res, err := r.applier.Apply(context.Background(), []spec.FileRef{ref})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Restart != RestartNotNeeded {
		t.Errorf("restart = %q, want %q", res.Restart, RestartNotNeeded)
	}
	if len(restart.rounds()) != 0 {
		t.Errorf("an unchanged file restarted an instance: %v", restart.rounds())
	}
}

// TestApplyManagedCertificateRestartsTheTunnelAndNotTheKernel is the ACME-1
// flow end to end: the panel delivers a renewed certificate as a managed file,
// the file is written, and the instance whose spec references it is restarted
// while the xray kernel is not asked to reload (a certificate is not an xray
// configuration file).
func TestApplyManagedCertificateRestartsTheTunnelAndNotTheKernel(t *testing.T) {
	r := newRig(t)
	name := "cert-7.pem"
	content := []byte("-----BEGIN CERTIFICATE-----\nnew\n-----END CERTIFICATE-----\n")
	ref := r.ref(name, content)
	certPath := filepath.Join(r.config, name)

	restart := &stubRestarter{}
	r.applier.SetRestarter(restart)
	r.applier.SetSource(desiredSource{
		files: []spec.FileRef{ref},
		d: spec.Desired{Instances: []spec.Instance{
			tunnelExit("exit", certPath, ""),
			tunnelExit("unrelated", filepath.Join(r.config, "cert-8.pem"), ""),
		}},
	})

	res, err := r.applier.Apply(context.Background(), []spec.FileRef{ref})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Status != StatusDone {
		t.Fatalf("status = %q (%v)", res.Status, res.Errors)
	}
	if got := r.read(name); got != string(content) {
		t.Errorf("%s = %q", name, got)
	}
	if res.Reload != ReloadNotNeeded {
		t.Errorf("reload = %q, want not_needed (a certificate is not an xray file)", res.Reload)
	}
	if n := r.reload.count(); n != 0 {
		t.Errorf("the xray kernel was reloaded %d time(s) for a certificate", n)
	}
	if res.Restart != RestartRestarted {
		t.Fatalf("restart = %q (failures %v)", res.Restart, res.RestartFailures)
	}
	if !reflect.DeepEqual(res.Restarted, []string{"exit"}) {
		t.Errorf("restarted = %v, want [exit]", res.Restarted)
	}
}

// TestRollbackRestartsTheInstancesThatReferenceTheRestoredFile: a rollback of a
// rejected file must reach the engines that read it at start-up too.
func TestRollbackRestartsTheInstancesThatReferenceTheRestoredFile(t *testing.T) {
	r := newRig(t)
	old := []byte(`{"rules":[{"type":"field","domain":["old.example"]}]}`)
	r.write(NameRoute, old)
	// The apply replaces it and fails the reload, which restores last_good.
	ref := r.ref(NameRoute, []byte(`{"rules":[{"type":"field","domain":["new.example"]}]}`))
	r.reload.err = errors.New("the kernel refused the reload")

	restart := &stubRestarter{}
	r.applier.SetRestarter(restart)
	r.applier.SetSource(desiredSource{
		files: []spec.FileRef{ref},
		d: spec.Desired{Instances: []spec.Instance{
			tunnelExit("exit", filepath.Join(r.config, NameRoute), ""),
		}},
	})

	res, err := r.applier.Apply(context.Background(), []spec.FileRef{ref})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Status != StatusRolledBack {
		t.Fatalf("status = %q, want rolled_back", res.Status)
	}
	if got := r.read(NameRoute); got != string(old) {
		t.Fatalf("the file was not restored: %q", got)
	}
	// The failed apply did not restart anything: the file is back to the bytes
	// the instance is already running.
	if len(restart.rounds()) != 0 {
		t.Errorf("a rolled-back apply restarted an instance: %v", restart.rounds())
	}

	// A second apply replaces it again (the reload now succeeds) and then the
	// panel rolls the files back: the restored file restarts the instance.
	r.reload.err = nil
	if _, err := r.applier.Apply(context.Background(), []spec.FileRef{ref}); err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	before := len(restart.rounds())
	rb, err := r.applier.Rollback(context.Background())
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if rb.Status != StatusRolledBack {
		t.Fatalf("rollback status = %q", rb.Status)
	}
	if rb.Restart != RestartRestarted {
		t.Fatalf("rollback restart = %q (failures %v)", rb.Restart, rb.RestartFailures)
	}
	if !reflect.DeepEqual(rb.Restarted, []string{"exit"}) {
		t.Errorf("rollback restarted = %v, want [exit]", rb.Restarted)
	}
	if got := len(restart.rounds()); got != before+1 {
		t.Errorf("restart rounds after the rollback = %d, want %d", got, before+1)
	}
}

// TestApplyRestartFailureIsReportedAndTheFilesStay is the failure rule: a
// restart that fails is reported with the reason, and the new bytes are NOT
// rolled back (they are valid, and the panel decides what to do with the
// instance).
func TestApplyRestartFailureIsReportedAndTheFilesStay(t *testing.T) {
	r := newRig(t)
	r.write(NameRoute, []byte(`{"rules":[]}`))
	content := []byte(`{"rules":[{"type":"field"}]}`)
	ref := r.ref(NameRoute, content)

	restart := &stubRestarter{err: errors.New("instance exit: process did not start")}
	r.applier.SetRestarter(restart)
	r.applier.SetSource(desiredSource{
		files: []spec.FileRef{ref},
		d: spec.Desired{Instances: []spec.Instance{
			tunnelExit("exit", filepath.Join(r.config, NameRoute), ""),
		}},
	})

	res, err := r.applier.Apply(context.Background(), []spec.FileRef{ref})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Status != StatusDone {
		t.Errorf("status = %q, want done (the file is applied)", res.Status)
	}
	if res.Reload != ReloadReloaded {
		t.Errorf("reload = %q, want reloaded", res.Reload)
	}
	if res.Restart != RestartFailed {
		t.Fatalf("restart = %q, want failed", res.Restart)
	}
	if len(res.RestartFailures) != 1 || !strings.Contains(res.RestartFailures[0], "instance exit") {
		t.Errorf("restart failures = %v, want the instance reason", res.RestartFailures)
	}
	if res.RolledBack {
		t.Error("a restart failure rolled the files back")
	}
	if got := r.read(NameRoute); got != string(content) {
		t.Errorf("the new file was rolled back: %q", got)
	}
}

// TestApplyWithoutARestarterReportsNotNeeded: an agent that cannot restart
// instances reports not_needed instead of pretending it did.
func TestApplyWithoutARestarterReportsNotNeeded(t *testing.T) {
	r := newRig(t)
	r.write(NameRoute, []byte(`{"rules":[]}`))
	ref := r.ref(NameRoute, []byte(`{"rules":[{"type":"field"}]}`))
	r.applier.SetSource(desiredSource{
		files: []spec.FileRef{ref},
		d: spec.Desired{Instances: []spec.Instance{
			tunnelExit("exit", filepath.Join(r.config, NameRoute), ""),
		}},
	})

	res, err := r.applier.Apply(context.Background(), []spec.FileRef{ref})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Restart != RestartNotNeeded {
		t.Errorf("restart = %q, want %q", res.Restart, RestartNotNeeded)
	}
	if len(res.Restarted) != 0 {
		t.Errorf("restarted = %v, want none", res.Restarted)
	}
}

// TestApplyRestartNeedsTheWholeDesiredState: a source that only reports the
// files (the panel link before anything was applied) cannot name an instance,
// so nothing is restarted.
func TestApplyRestartNeedsTheWholeDesiredState(t *testing.T) {
	r := newRig(t)
	r.write(NameRoute, []byte(`{"rules":[]}`))
	ref := r.ref(NameRoute, []byte(`{"rules":[{"type":"field"}]}`))

	restart := &stubRestarter{}
	r.applier.SetRestarter(restart)
	r.applier.SetSource(SourceFunc(func() []spec.FileRef { return []spec.FileRef{ref} }))

	res, err := r.applier.Apply(context.Background(), []spec.FileRef{ref})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Restart != RestartNotNeeded {
		t.Errorf("restart = %q, want %q", res.Restart, RestartNotNeeded)
	}
	if len(restart.rounds()) != 0 {
		t.Errorf("the restarter was called without a desired state: %v", restart.rounds())
	}
}
