package xraysvc

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"github.com/W1nCwC/W1nCray/agent/xrayapi"
)

// writeAddrFile writes the kernel's loopback address file (the Windows shape,
// which the Unix resolution also falls back to when no socket exists).
func writeAddrFile(path, addr string) error {
	return os.WriteFile(path, []byte(addr), 0o600)
}

// auditKernel is a stand-in for the kernel's local endpoint: it serves the
// audit routes exactly as xraynode does, so the client is tested against the
// real wire shape and not a mock.
type auditKernel struct {
	srv *httptest.Server

	mu sync.Mutex
	// status is the document GET /status answers.
	status xrayapi.Status
	// batches are handed out in order; a request past the end gets an empty
	// page at the last batch's epoch.
	batches []xrayapi.AuditBatch
	calls   int
	// enabled is the switch POST /audit/ctl wrote.
	enabled bool
	// ctlBody is the raw body of the last /audit/ctl request.
	ctlBody []byte
	// after/max are the query parameters of the last /audit request.
	after uint64
	max   int
	// noAuditRoute makes the audit routes answer 404, like a kernel that
	// predates them.
	noAuditRoute bool
	// statusErr makes GET /status answer 500.
	statusErr bool
}

func newAuditKernel(t *testing.T, status xrayapi.Status, batches ...xrayapi.AuditBatch) *auditKernel {
	t.Helper()
	k := &auditKernel{status: status, batches: batches}
	mux := http.NewServeMux()
	mux.HandleFunc(xrayapi.StatusPath, func(w http.ResponseWriter, r *http.Request) {
		if k.statusErr {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(k.status)
	})
	mux.HandleFunc(xrayapi.AuditPath, func(w http.ResponseWriter, r *http.Request) {
		if k.noAuditRoute {
			http.NotFound(w, r)
			return
		}
		k.mu.Lock()
		k.after, _ = strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
		k.max, _ = strconv.Atoi(r.URL.Query().Get("max"))
		i := k.calls
		k.calls++
		var batch xrayapi.AuditBatch
		switch {
		case i < len(k.batches):
			batch = k.batches[i]
		case len(k.batches) > 0:
			batch = xrayapi.AuditBatch{Epoch: k.batches[len(k.batches)-1].Epoch, Items: []xrayapi.AuditItem{}}
		default:
			batch = xrayapi.AuditBatch{Items: []xrayapi.AuditItem{}}
		}
		k.mu.Unlock()
		_ = json.NewEncoder(w).Encode(batch)
	})
	mux.HandleFunc(xrayapi.AuditCtlPath, func(w http.ResponseWriter, r *http.Request) {
		if k.noAuditRoute {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var req xrayapi.AuditCtlRequest
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &req)
		k.mu.Lock()
		k.enabled = req.Enabled
		k.ctlBody = body
		k.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})
	k.srv = httptest.NewServer(mux)
	t.Cleanup(k.srv.Close)
	return k
}

func (k *auditKernel) client(t *testing.T, status xrayapi.Service) *AuditClient {
	t.Helper()
	c, err := NewAuditClient(AuditOptions{BaseURL: k.srv.URL, Status: status})
	if err != nil {
		t.Fatalf("NewAuditClient: %v", err)
	}
	return c
}

func (k *auditKernel) lastRequest() (after uint64, max int) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.after, k.max
}

func (k *auditKernel) switchState() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.enabled
}

// fakeAuditStatus is the xrayapi.Service side of the test: only Status is used by
// the audit client.
type fakeAuditStatus struct {
	mu  sync.Mutex
	st  xrayapi.Status
	err error
}

func (f *fakeAuditStatus) Status(context.Context) (xrayapi.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.st, f.err
}

func (f *fakeAuditStatus) CheckStaged(context.Context, string, []string) (xrayapi.StagedResult, error) {
	return xrayapi.StagedResult{}, nil
}

func (f *fakeAuditStatus) WaitReloaded(context.Context, string) error { return nil }

func (f *fakeAuditStatus) SyncMachineNodes(context.Context) (bool, error) { return false, nil }

// TestAuditSupportedFollowsTheKernelStatusBit pins the capability rule: the
// kernel's own status document decides, and the route is not asked at all when
// the status answered.
func TestAuditSupportedFollowsTheKernelStatusBit(t *testing.T) {
	k := newAuditKernel(t, xrayapi.Status{Version: "0.6.0", Running: true, Audit: true})
	st := &fakeAuditStatus{st: xrayapi.Status{Audit: true}}
	c := k.client(t, st)

	ok, err := c.Supported(context.Background())
	if err != nil || !ok {
		t.Fatalf("Supported() = %v, %v; want true, nil", ok, err)
	}
	// No audit request may have been made: the status bit is authoritative.
	if after, max := k.lastRequest(); after != 0 || max != 0 {
		t.Errorf("Supported() hit the audit route (after=%d max=%d)", after, max)
	}

	st.mu.Lock()
	st.st = xrayapi.Status{Audit: false}
	st.mu.Unlock()
	if ok, err := c.Supported(context.Background()); err != nil || ok {
		t.Fatalf("Supported() = %v, %v; want false, nil", ok, err)
	}
}

// TestAuditSupportedFallsBackToTheRoute covers the wiring without a status
// reader: the route itself is asked, and a 404 means "this kernel predates the
// collector" rather than an error.
func TestAuditSupportedFallsBackToTheRoute(t *testing.T) {
	k := newAuditKernel(t, xrayapi.Status{Audit: true})
	c := k.client(t, nil)
	if ok, err := c.Supported(context.Background()); err != nil || !ok {
		t.Fatalf("Supported() = %v, %v; want true, nil", ok, err)
	}

	old := newAuditKernel(t, xrayapi.Status{})
	old.noAuditRoute = true
	c2 := old.client(t, nil)
	if ok, err := c2.Supported(context.Background()); err != nil || ok {
		t.Fatalf("Supported() on an old kernel = %v, %v; want false, nil", ok, err)
	}
}

// TestAuditSupportedReportsAnUnreachableKernelAsAnError pins that a kernel that
// cannot be reached is not silently reported as unsupported: the caller must
// know the difference, because only the second answer is final.
func TestAuditSupportedReportsAnUnreachableKernelAsAnError(t *testing.T) {
	k := newAuditKernel(t, xrayapi.Status{Audit: true})
	st := &fakeAuditStatus{err: errors.New("connection refused")}
	c := k.client(t, st)
	if ok, err := c.Supported(context.Background()); err == nil || ok {
		t.Fatalf("Supported() = %v, %v; want false, an error", ok, err)
	}
}

// TestAuditBatchSendsTheCursorAndThePageSize covers the request shape: after
// and max are the caller's, max is clamped to the contract's bound, and the
// page comes back with Supported=true.
func TestAuditBatchSendsTheCursorAndThePageSize(t *testing.T) {
	k := newAuditKernel(t, xrayapi.Status{Audit: true}, xrayapi.AuditBatch{
		Epoch:   1000,
		FromSeq: 41,
		ToSeq:   42,
		Items: []xrayapi.AuditItem{
			{T: 1700000000000, L: "accepted tcp:1.2.3.4:1234 [x -> y]"},
			{T: 1700000000001, L: "accepted tcp:5.6.7.8:4321 [x -> y]"},
		},
		More: true,
	})
	c := k.client(t, nil)

	page, err := c.Batch(context.Background(), 40, 400)
	if err != nil {
		t.Fatalf("Batch: %v", err)
	}
	if !page.Supported {
		t.Fatal("Batch reported Supported=false for a kernel that serves /audit")
	}
	if page.Batch.Epoch != 1000 || page.Batch.FromSeq != 41 || page.Batch.ToSeq != 42 || !page.Batch.More {
		t.Errorf("batch = %+v", page.Batch)
	}
	if len(page.Batch.Items) != 2 || page.Batch.Items[0].L == "" || page.Batch.Items[0].T != 1700000000000 {
		t.Errorf("items = %+v", page.Batch.Items)
	}
	if after, max := k.lastRequest(); after != 40 || max != 400 {
		t.Errorf("request after=%d max=%d, want 40/400", after, max)
	}

	// max above the contract bound is clamped, never forwarded.
	if _, err := c.Batch(context.Background(), 0, 100000); err != nil {
		t.Fatalf("Batch: %v", err)
	}
	if _, max := k.lastRequest(); max != xrayapi.MaxAuditItems {
		t.Errorf("max = %d, want %d", max, xrayapi.MaxAuditItems)
	}
}

// TestAuditBatchReportsAnOldKernelAsUnsupported covers the degradation rule: a
// 404 is a fact about the kernel, not a failure of the caller.
func TestAuditBatchReportsAnOldKernelAsUnsupported(t *testing.T) {
	k := newAuditKernel(t, xrayapi.Status{})
	k.noAuditRoute = true
	c := k.client(t, nil)
	page, err := c.Batch(context.Background(), 0, 400)
	if err != nil {
		t.Fatalf("Batch: %v", err)
	}
	if page.Supported || len(page.Batch.Items) != 0 {
		t.Errorf("page = %+v, want an unsupported empty page", page)
	}
}

// TestAuditSetEnabledPostsTheSwitch covers the control request and its
// degradation: the body is the contract's {"enabled":bool}, and an old kernel
// is reported as ErrAuditUnsupported instead of a transport error.
func TestAuditSetEnabledPostsTheSwitch(t *testing.T) {
	k := newAuditKernel(t, xrayapi.Status{Audit: true})
	c := k.client(t, nil)

	if err := c.SetEnabled(context.Background(), true); err != nil {
		t.Fatalf("SetEnabled(true): %v", err)
	}
	if !k.switchState() {
		t.Error("the kernel's switch was not turned on")
	}
	k.mu.Lock()
	body := string(k.ctlBody)
	k.mu.Unlock()
	if body != `{"enabled":true}` {
		t.Errorf("ctl body = %s, want {\"enabled\":true}", body)
	}

	if err := c.SetEnabled(context.Background(), false); err != nil {
		t.Fatalf("SetEnabled(false): %v", err)
	}
	if k.switchState() {
		t.Error("the kernel's switch was not turned off")
	}

	old := newAuditKernel(t, xrayapi.Status{})
	old.noAuditRoute = true
	c2 := old.client(t, nil)
	err := c2.SetEnabled(context.Background(), true)
	if !IsAuditUnsupported(err) {
		t.Fatalf("SetEnabled on an old kernel = %v, want ErrAuditUnsupported", err)
	}
}

// TestNewAuditClientRequiresAnEndpoint keeps the constructor honest: a client
// without a base URL or a config path could only fail later, at request time.
func TestNewAuditClientRequiresAnEndpoint(t *testing.T) {
	if _, err := NewAuditClient(AuditOptions{}); err == nil {
		t.Fatal("NewAuditClient accepted no endpoint at all")
	}
	if _, err := NewAuditClient(AuditOptions{BaseURL: "http://127.0.0.1:1"}); err != nil {
		t.Fatalf("NewAuditClient with a base URL: %v", err)
	}
	if _, err := NewAuditClient(AuditOptions{ConfigPath: "/etc/W1nCray/config.yml"}); err != nil {
		t.Fatalf("NewAuditClient with a config path: %v", err)
	}
}

// TestAuditEndpointNeedsAReachableKernel pins the endpoint resolution contract
// of a config path: on a machine where the kernel never started there is
// nothing to read, and the error says so instead of dialing something else.
func TestAuditEndpointNeedsAReachableKernel(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := auditEndpoint(filepath.Join(dir, "config.yml")); err == nil {
		t.Fatal("auditEndpoint resolved an endpoint with no kernel running")
	}
	// The Windows shape (an address file) is what a config path can also
	// resolve on Unix when the socket is absent, so write one and check that
	// the address is used verbatim.
	if err := writeAddrFile(filepath.Join(dir, xrayapi.StatusAddrName), "127.0.0.1:9\n"); err != nil {
		t.Fatalf("write the address file: %v", err)
	}
	client, base, err := auditEndpoint(filepath.Join(dir, "config.yml"))
	if err != nil {
		t.Fatalf("auditEndpoint with an address file: %v", err)
	}
	if base != "http://127.0.0.1:9" {
		t.Errorf("base = %q, want http://127.0.0.1:9", base)
	}
	if client == nil {
		t.Error("auditEndpoint returned no HTTP client")
	}
}
