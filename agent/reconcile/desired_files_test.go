package reconcile

import (
	"context"
	"strings"
	"testing"

	"github.com/W1nCwC/W1nCray/agent/spec"
)

// TestLastDesiredKeepsAndCopiesTheFilesSection covers the source the managed-file
// commands read: the desired state's "files" section must survive an Apply and
// the persistence round trip, and the returned slice must be a copy.
func TestLastDesiredKeepsAndCopiesTheFilesSection(t *testing.T) {
	e := newEnv(t)
	files := []spec.FileRef{
		{Name: "route.json", SHA256: strings.Repeat("a", 64), Size: 12},
		{Name: "geoip.dat", SHA256: strings.Repeat("b", 64), Size: 1024, Kernel: "xray"},
	}
	d := spec.Desired{Version: 1, Revision: 4, Instances: []spec.Instance{}, Files: files}
	if _, err := e.r.Apply(context.Background(), d); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	got := e.r.LastDesired()
	if len(got.Files) != 2 || got.Files[1].Kernel != "xray" {
		t.Fatalf("LastDesired().Files = %+v", got.Files)
	}
	// The caller cannot mutate the state the reconciler holds.
	got.Files[0].Name = "mutated"
	if again := e.r.LastDesired(); again.Files[0].Name != "route.json" {
		t.Errorf("LastDesired aliased the stored slice: %+v", again.Files)
	}
	// The section survives the last_good persistence used at start-up.
	sn, ok, err := e.st.LoadLastGood()
	if err != nil || !ok {
		t.Fatalf("LoadLastGood: ok=%v err=%v", ok, err)
	}
	if len(sn.Desired.Files) != 2 || sn.Desired.Files[0] != files[0] {
		t.Errorf("persisted files = %+v, want %+v", sn.Desired.Files, files)
	}
}

// TestLastDesiredIsEmptyBeforeTheFirstApply keeps the accessor total.
func TestLastDesiredIsEmptyBeforeTheFirstApply(t *testing.T) {
	e := newEnv(t)
	if got := e.r.LastDesired(); len(got.Files) != 0 {
		t.Errorf("LastDesired on a fresh reconciler = %+v", got.Files)
	}
}
