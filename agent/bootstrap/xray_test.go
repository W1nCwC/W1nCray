package bootstrap

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"

	"github.com/W1nCwC/W1nCray/agent/filesync"
	"github.com/W1nCwC/W1nCray/agent/xrayapi"
)

// fakeXray is a stand-in for the W1nCray-xray kernel service.
type fakeXray struct {
	res      xrayapi.StagedResult
	err      error
	gotDir   string
	gotFiles []string
	// syncChanged/syncErr script the SyncMachineNodes answer; syncMu guards the
	// counter, because the "nodes" hint runs on the WebSocket serve goroutine.
	syncChanged bool
	syncErr     error
	syncMu      sync.Mutex
	syncCalls   int
}

func (f *fakeXray) Status(context.Context) (xrayapi.Status, error) { return xrayapi.Status{}, nil }

func (f *fakeXray) CheckStaged(_ context.Context, dir string, files []string) (xrayapi.StagedResult, error) {
	f.gotDir, f.gotFiles = dir, files
	return f.res, f.err
}

func (f *fakeXray) WaitReloaded(context.Context, string) error { return nil }

func (f *fakeXray) SyncMachineNodes(context.Context) (bool, error) {
	f.syncMu.Lock()
	defer f.syncMu.Unlock()
	f.syncCalls++
	return f.syncChanged, f.syncErr
}

// syncCallCount is the number of SyncMachineNodes calls so far.
func (f *fakeXray) syncCallCount() int {
	f.syncMu.Lock()
	defer f.syncMu.Unlock()
	return f.syncCalls
}

// TestFilesValidatorWithoutXrayKernel is the nil-safe degradation PLAN v11 §D
// asks for: a machine without the kernel must refuse managed Xray files with an
// explicit reason instead of half-applying a file set no instance would read.
func TestFilesValidatorWithoutXrayKernel(t *testing.T) {
	errs := filesValidator(nil).ValidateStaged(context.Background(), t.TempDir(), nil)
	if len(errs) != 1 || errs[0].Error() != "Xray 内核未安装" {
		t.Fatalf("errors = %v, want the single \"Xray 内核未安装\"", errs)
	}
}

// TestFilesValidatorUsesTheKernel: with a kernel service wired, the staged set
// is checked by the kernel and its JSON error list is flattened (the file name
// is kept as the error prefix).
func TestFilesValidatorUsesTheKernel(t *testing.T) {
	f := &fakeXray{res: xrayapi.StagedResult{Errors: []xrayapi.StagedError{
		{File: filesync.NameRoute, Message: "rules[0] unknown field"},
		{Message: "xray instance pre-check: duplicate tag"},
	}}}
	errs := filesValidator(f).ValidateStaged(context.Background(), "/staged", []filesync.FileRef{
		{Name: filesync.NameRoute}, {Name: filesync.NameDNS},
	})
	if f.gotDir != "/staged" || !reflect.DeepEqual(f.gotFiles, []string{filesync.NameRoute, filesync.NameDNS}) {
		t.Fatalf("kernel called with dir=%q files=%v", f.gotDir, f.gotFiles)
	}
	if len(errs) != 2 ||
		errs[0].Error() != "route.json: rules[0] unknown field" ||
		errs[1].Error() != "xray instance pre-check: duplicate tag" {
		t.Fatalf("errors = %v", errs)
	}

	// A kernel that reports ok returns no errors.
	f2 := &fakeXray{res: xrayapi.StagedResult{OK: true}}
	if errs := filesValidator(f2).ValidateStaged(context.Background(), "/staged", nil); len(errs) != 0 {
		t.Fatalf("errors = %v, want none", errs)
	}

	// A transport error is reported as is.
	f3 := &fakeXray{err: errors.New("dial unix /etc/W1nCray/xray.sock: connect: no such file")}
	errs = filesValidator(f3).ValidateStaged(context.Background(), "/staged", nil)
	if len(errs) != 1 || !errors.Is(errs[0], f3.err) {
		t.Fatalf("errors = %v, want the transport error", errs)
	}
}
