package opscmd

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/panelclient"
	"github.com/W1nCwC/W1nCray/agent/spec"
	"github.com/W1nCwC/W1nCray/kernel/install"
)

// fakeKernels is the KernelOps surface with no disk behind it. The tests that
// must prove real installer behaviour (refusing the current version, clearing
// the previous pointer, swapping the pointers) use the real installer in
// kernel_test.go instead.
type fakeKernels struct {
	list      []install.Entry
	catalog   []install.CatalogEntry
	listFn    func() ([]install.Entry, error)
	catalogFn func() ([]install.CatalogEntry, error)
	running   string
	exact     bool
	ensureFn  func(ctx context.Context, pin spec.KernelPin) (driver.Installed, error)
	removeFn  func(name, version string) error
	rollFn    func(name string) (driver.Installed, error)
}

func (f fakeKernels) List() ([]install.Entry, error) {
	if f.listFn != nil {
		return f.listFn()
	}
	return f.list, nil
}
func (f fakeKernels) Catalog() ([]install.CatalogEntry, error) {
	if f.catalogFn != nil {
		return f.catalogFn()
	}
	return f.catalog, nil
}
func (f fakeKernels) Ensure(ctx context.Context, pin spec.KernelPin) (driver.Installed, error) {
	if f.ensureFn != nil {
		return f.ensureFn(ctx, pin)
	}
	return driver.Installed{Version: pin.Version}, nil
}
func (f fakeKernels) Remove(name, version string) error {
	if f.removeFn != nil {
		return f.removeFn(name, version)
	}
	return nil
}
func (f fakeKernels) Rollback(name string) (driver.Installed, error) {
	if f.rollFn != nil {
		return f.rollFn(name)
	}
	return driver.Installed{Version: "1.0.0"}, nil
}
func (f fakeKernels) RunningVersion(name string) (string, bool) { return f.running, f.exact }

func mustRegistry(t *testing.T, d Deps) *Registry {
	t.Helper()
	if d.Kernels == nil {
		d.Kernels = fakeKernels{}
	}
	r, err := New(d)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r
}

// decodeFailure reads the {"error","code"} body of a failed command.
func decodeFailure(t *testing.T, res json.RawMessage) failure {
	t.Helper()
	var f failure
	if err := json.Unmarshal(res, &f); err != nil {
		t.Fatalf("failure body %s: %v", res, err)
	}
	return f
}

// TestRegistryWhitelistIsTheRegisteredTypes covers the framework contract: the
// whitelist is exactly the registered types, and an unknown type is answered
// with the historical "unsupported command" failure, never executed. The file
// commands are registered too: a registry without a file applier answers them
// with an explicit not_supported rather than pretending the type does not
// exist (protocol ruling 5).
func TestRegistryWhitelistIsTheRegisteredTypes(t *testing.T) {
	reg := mustRegistry(t, Deps{})
	want := []string{
		panelclient.CmdComponentRestart,
		panelclient.CmdFilesApply,
		panelclient.CmdFilesRollback,
		panelclient.CmdFilesValidate,
		panelclient.CmdKernelInstall,
		panelclient.CmdKernelList,
		panelclient.CmdKernelRemove,
		panelclient.CmdKernelRollback,
	}
	got := reg.Types()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("Types() = %v, want %v", got, want)
	}
	for _, typ := range want {
		if !reg.Has(typ) {
			t.Errorf("Has(%q) = false", typ)
		}
	}
	if reg.Has("rm -rf /") || reg.Has(panelclient.CmdRefresh) || reg.Has(panelclient.CmdDumpState) {
		t.Error("the whitelist must not contain unregistered or built-in types")
	}

	status, res := reg.Execute(context.Background(), panelclient.Command{ID: "u1", Type: "rm -rf /"})
	if status != panelclient.ResultFailed {
		t.Fatalf("unknown type status = %q, want failed", status)
	}
	f := decodeFailure(t, res)
	if f.Error != "unsupported command" {
		t.Errorf("unknown type error = %q, want %q", f.Error, "unsupported command")
	}
	if f.Code != "" {
		t.Errorf("unknown type code = %q, want none", f.Code)
	}
}

// TestRegisterRejectsBadEntries pins the plugin contract: no empty type, no nil
// handler, no silent replacement of an existing command.
func TestRegisterRejectsBadEntries(t *testing.T) {
	reg := mustRegistry(t, Deps{})
	h := func(context.Context, Request, Completion) (Result, error) { return done(nil), nil }
	if err := reg.Register("", h); err == nil {
		t.Error("empty type accepted")
	}
	if err := reg.Register("ok", nil); err == nil {
		t.Error("nil handler accepted")
	}
	if err := reg.Register("ok", h); err != nil {
		t.Fatalf("first registration: %v", err)
	}
	if err := reg.Register("ok", h); err == nil {
		t.Error("duplicate registration accepted")
	}
}

type sinkCall struct {
	id, status string
	data       json.RawMessage
}

// TestLongCommandAnswersAcceptedThenDone covers contract ruling 7 end to end at
// the framework level: Execute returns "accepted" at once and the final result
// arrives later through the sink, with the same id.
func TestLongCommandAnswersAcceptedThenDone(t *testing.T) {
	calls := make(chan sinkCall, 4)
	reg := mustRegistry(t, Deps{Sink: SinkFunc(func(id, status string, data json.RawMessage) {
		calls <- sinkCall{id: id, status: status, data: data}
	})})
	if err := reg.Register("test_long", func(ctx context.Context, req Request, complete Completion) (Result, error) {
		go func() {
			time.Sleep(5 * time.Millisecond)
			complete(StatusDone, mustJSON(map[string]string{"phase": "two"}), nil)
		}()
		return accepted(), nil
	}); err != nil {
		t.Fatal(err)
	}

	status, res := reg.Execute(context.Background(), panelclient.Command{ID: "L1", Type: "test_long"})
	if status != panelclient.ResultAccepted {
		t.Fatalf("first answer = (%q, %s), want accepted", status, res)
	}
	if len(res) != 0 {
		t.Errorf("accepted result = %s, want empty", res)
	}
	select {
	case c := <-calls:
		if c.id != "L1" || c.status != panelclient.ResultDone {
			t.Errorf("final call = %+v, want id L1 status done", c)
		}
		var body map[string]string
		if err := json.Unmarshal(c.data, &body); err != nil || body["phase"] != "two" {
			t.Errorf("final result = %s (%v)", c.data, err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the final result never arrived")
	}
}

// TestCompletionDeliversOnlyOnce keeps a handler bug from answering a command
// twice.
func TestCompletionDeliversOnlyOnce(t *testing.T) {
	calls := make(chan sinkCall, 4)
	reg := mustRegistry(t, Deps{Sink: SinkFunc(func(id, status string, data json.RawMessage) {
		calls <- sinkCall{id: id, status: status, data: data}
	})})
	if err := reg.Register("test_twice", func(ctx context.Context, req Request, complete Completion) (Result, error) {
		complete(StatusDone, mustJSON(map[string]int{"n": 1}), nil)
		complete(StatusFailed, nil, errors.New("second call"))
		return accepted(), nil
	}); err != nil {
		t.Fatal(err)
	}
	if status, _ := reg.Execute(context.Background(), panelclient.Command{ID: "T1", Type: "test_twice"}); status != panelclient.ResultAccepted {
		t.Fatalf("status = %q, want accepted", status)
	}
	if c := <-calls; c.status != panelclient.ResultDone {
		t.Fatalf("first delivered call = %+v, want done", c)
	}
	select {
	case c := <-calls:
		t.Fatalf("the completion was delivered twice: %+v", c)
	case <-time.After(50 * time.Millisecond):
	}
}

// TestHandlerErrorsCarryACode covers the machine-readable failure contract.
func TestHandlerErrorsCarryACode(t *testing.T) {
	reg := mustRegistry(t, Deps{})
	if err := reg.Register("test_fail", func(ctx context.Context, req Request, complete Completion) (Result, error) {
		return Result{}, coded("boom", errors.New("it broke"))
	}); err != nil {
		t.Fatal(err)
	}
	status, res := reg.Execute(context.Background(), panelclient.Command{ID: "F1", Type: "test_fail"})
	if status != panelclient.ResultFailed {
		t.Fatalf("status = %q, want failed", status)
	}
	f := decodeFailure(t, res)
	if f.Error != "it broke" || f.Code != "boom" {
		t.Errorf("failure = %+v, want error %q code %q", f, "it broke", "boom")
	}
}

// TestCommandArgsAreDecodedStrictly covers the argument contract: an unknown
// field, a missing required field and an invalid name are all refused before
// anything runs.
func TestCommandArgsAreDecodedStrictly(t *testing.T) {
	reg := mustRegistry(t, Deps{})
	cases := []struct {
		name string
		typ  string
		args string
		want string
	}{
		{"unknown field", panelclient.CmdKernelRemove, `{"name":"gost","version":"1.0.0","extra":1}`, "invalid_args"},
		{"missing version", panelclient.CmdKernelRemove, `{"name":"gost"}`, "invalid_args"},
		{"missing name", panelclient.CmdKernelRemove, `{"version":"1.0.0"}`, "invalid_args"},
		{"wrong type", panelclient.CmdKernelRemove, `{"name":7,"version":"1.0.0"}`, "invalid_args"},
		{"malformed json", panelclient.CmdKernelRemove, `{"name":`, "invalid_args"},
		{"invalid name", panelclient.CmdKernelInstall, `{"name":"GOST!"}`, "invalid_args"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, res := reg.Execute(context.Background(), panelclient.Command{ID: "a1", Type: tc.typ, Args: json.RawMessage(tc.args)})
			if status != panelclient.ResultFailed {
				t.Fatalf("status = %q, want failed (%s)", status, res)
			}
			if got := decodeFailure(t, res).Code; got != tc.want {
				t.Errorf("code = %q, want %q (%s)", got, tc.want, res)
			}
		})
	}
}

// TestReservedAgentNameIsRefused covers ruling 11: the name "agent" belongs to
// self_update, so every kernel command and component_restart refuses it.
func TestReservedAgentNameIsRefused(t *testing.T) {
	reg := mustRegistry(t, Deps{})
	for _, tc := range []struct {
		typ  string
		args string
	}{
		{panelclient.CmdKernelInstall, `{"name":"agent"}`},
		{panelclient.CmdKernelInstall, `{"name":"agent","version":"1.0.0"}`},
		{panelclient.CmdKernelRemove, `{"name":"agent","version":"1.0.0"}`},
		{panelclient.CmdKernelRollback, `{"name":"agent"}`},
		{panelclient.CmdComponentRestart, `{"name":"agent"}`},
	} {
		status, res := reg.Execute(context.Background(), panelclient.Command{ID: "r1", Type: tc.typ, Args: json.RawMessage(tc.args)})
		if status != panelclient.ResultFailed {
			t.Fatalf("%s: status = %q, want failed (%s)", tc.typ, status, res)
		}
		if f := decodeFailure(t, res); f.Code != "reserved_name" {
			t.Errorf("%s: code = %q, want reserved_name (%s)", tc.typ, f.Code, res)
		}
	}
}

type fakeComp struct{ calls []string }

func (c *fakeComp) Restart(ctx context.Context, name string) (int, error) {
	c.calls = append(c.calls, name)
	return len(c.calls), nil
}

// TestComponentRestartRefusesAgentAndXray pins the two refusals: the agent is
// not a kernel process, and the embedded xray engine shares the agent process.
func TestComponentRestartRefusesAgentAndXray(t *testing.T) {
	comp := &fakeComp{}
	reg := mustRegistry(t, Deps{Comp: comp})

	status, res := reg.Execute(context.Background(), panelclient.Command{
		ID: "c1", Type: panelclient.CmdComponentRestart, Args: json.RawMessage(`{"name":"agent"}`),
	})
	if status != panelclient.ResultFailed || decodeFailure(t, res).Code != "reserved_name" {
		t.Fatalf("agent restart = (%q, %s), want failed reserved_name", status, res)
	}
	status, res = reg.Execute(context.Background(), panelclient.Command{
		ID: "c2", Type: panelclient.CmdComponentRestart, Args: json.RawMessage(`{"name":"xray"}`),
	})
	if status != panelclient.ResultFailed {
		t.Fatalf("xray restart status = %q, want failed (%s)", status, res)
	}
	f := decodeFailure(t, res)
	if f.Code != "embedded" || !strings.Contains(f.Error, "embedded") {
		t.Errorf("xray restart failure = %+v, want code embedded", f)
	}
	if len(comp.calls) != 0 {
		t.Errorf("a refused restart reached the component layer: %v", comp.calls)
	}

	// A real kernel component is restarted.
	status, res = reg.Execute(context.Background(), panelclient.Command{
		ID: "c3", Type: panelclient.CmdComponentRestart, Args: json.RawMessage(`{"name":"gost"}`),
	})
	if status != panelclient.ResultDone {
		t.Fatalf("gost restart = (%q, %s), want done", status, res)
	}
	var out restartedResult
	if err := json.Unmarshal(res, &out); err != nil || out.Name != "gost" || out.Restarted != 1 {
		t.Errorf("gost restart result = %s (%v)", res, err)
	}
	if len(comp.calls) != 1 || comp.calls[0] != "gost" {
		t.Errorf("component calls = %v, want [gost]", comp.calls)
	}
}

// TestKernelListWithoutAManifestKeepsTheInstalledVersions covers design section
// 3.2: a missing catalog (no signed manifest) empties catalog but never hides
// the installed versions, and "in use" follows RunningVersion when the platform
// can tell.
func TestKernelListWithoutAManifestKeepsTheInstalledVersions(t *testing.T) {
	installed := []install.Entry{
		{Name: "gost", Version: "2.0.0", Current: true, Path: "/k/gost/2.0.0/gost", Size: 2048, InstalledAt: time.Unix(1700000000, 0)},
		{Name: "gost", Version: "1.0.0", Previous: true, Path: "/k/gost/1.0.0/gost", Size: 1024},
	}
	reg := mustRegistry(t, Deps{Kernels: fakeKernels{
		list:    installed,
		running: "1.0.0",
		exact:   true,
		catalog: nil,
	}})
	status, res := reg.Execute(context.Background(), panelclient.Command{ID: "k1", Type: panelclient.CmdKernelList})
	if status != panelclient.ResultDone {
		t.Fatalf("kernel_list = (%q, %s), want done", status, res)
	}
	var out panelclient.KernelListResult
	if err := json.Unmarshal(res, &out); err != nil {
		t.Fatalf("kernel_list result %s: %v", res, err)
	}
	if len(out.Kernels) != 2 {
		t.Fatalf("kernels = %+v, want 2 entries", out.Kernels)
	}
	byVersion := map[string]struct {
		current, previous, inUse bool
	}{}
	for _, e := range out.Kernels {
		byVersion[e.Version] = struct {
			current, previous, inUse bool
		}{e.Current, e.Previous, e.InUse}
	}
	if b := byVersion["2.0.0"]; !b.current || b.previous || b.inUse {
		t.Errorf("2.0.0 = %+v, want current, not previous, not in use", b)
	}
	if b := byVersion["1.0.0"]; b.current || !b.previous || !b.inUse {
		t.Errorf("1.0.0 = %+v, want previous and in use (a live process runs it)", b)
	}
	if out.Catalog == nil || len(out.Catalog) != 0 {
		t.Errorf("catalog = %+v, want an empty list", out.Catalog)
	}
	if out.Kernels[0].SizeBytes == 0 || out.Kernels[0].InstalledAt == 0 || out.Kernels[0].Path == "" {
		t.Errorf("kernel entry lost size/installed_at/path: %+v", out.Kernels[0])
	}
}

// TestKernelListFallsBackToTheCurrentPointer keeps the degraded mode honest:
// when RunningVersion cannot tell (exact=false), "in use" is the current
// pointer, never an invented process match.
func TestKernelListFallsBackToTheCurrentPointer(t *testing.T) {
	reg := mustRegistry(t, Deps{Kernels: fakeKernels{
		list: []install.Entry{
			{Name: "gost", Version: "2.0.0", Current: true},
			{Name: "gost", Version: "1.0.0", Previous: true},
		},
		running: "1.0.0", exact: false,
	}})
	_, res := reg.Execute(context.Background(), panelclient.Command{ID: "k2", Type: panelclient.CmdKernelList})
	var out panelclient.KernelListResult
	if err := json.Unmarshal(res, &out); err != nil {
		t.Fatal(err)
	}
	for _, e := range out.Kernels {
		if want := e.Current; e.InUse != want {
			t.Errorf("%s in_use = %v, want the current pointer %v", e.Version, e.InUse, want)
		}
	}
}

// TestKernelListCatalogOnlyOffersAvailableVersions: a version this machine
// cannot install must not be offered.
func TestKernelListCatalogOnlyOffersAvailableVersions(t *testing.T) {
	reg := mustRegistry(t, Deps{Kernels: fakeKernels{catalog: []install.CatalogEntry{
		{Name: "gost", Version: "2.0.0", Available: true},
		{Name: "gost", Version: "1.9.0", Available: false, Reason: "no target"},
		{Name: "realm", Version: "2.9.6", Available: true},
	}}})
	_, res := reg.Execute(context.Background(), panelclient.Command{ID: "k3", Type: panelclient.CmdKernelList})
	var out panelclient.KernelListResult
	if err := json.Unmarshal(res, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Catalog) != 2 || out.Catalog[0].Name != "gost" || out.Catalog[1].Name != "realm" {
		t.Fatalf("catalog = %+v", out.Catalog)
	}
	if len(out.Catalog[0].Versions) != 1 || out.Catalog[0].Versions[0] != "2.0.0" {
		t.Errorf("gost versions = %v, want only the available 2.0.0", out.Catalog[0].Versions)
	}
}
