package xraynode

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	xlog "github.com/xtls/xray-core/common/log"

	"github.com/W1nCwC/W1nCray/agent/xrayapi"
)

// auditConfigBody is a minimal kernel configuration that logs access and error
// output to files under dir, so a test can prove the collector does not change
// what the original logger writes.
func auditConfigBody(dir string) string {
	return fmt.Sprintf(`Log:
  Level: info
  AccessPath: %q
  ErrorPath: %q
Agent:
  Enabled: true
`, filepath.Join(dir, "access.log"), filepath.Join(dir, "error.log"))
}

// startAuditService starts a kernel service for a config in dir and returns it
// with its local status endpoint. The caller closes both.
func startAuditService(t *testing.T, dir string) (*Service, *StatusServer) {
	t.Helper()
	t.Setenv(xrayapi.RuntimeDirEnv, t.TempDir())
	configPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(configPath, []byte(auditConfigBody(dir)), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	svc := New(configPath, cfg)
	if err := svc.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	srv, err := NewStatusServer(svc, dir)
	if err != nil {
		svc.Close()
		t.Fatalf("NewStatusServer: %v", err)
	}
	return svc, srv
}

// auditClient talks to the local status endpoint the way the agent does.
func auditClient(s *StatusServer) *http.Client {
	network := "unix"
	if runtime.GOOS == "windows" {
		network = "tcp"
	}
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, s.addr)
			},
		},
		Timeout: 5 * time.Second,
	}
}

// getAudit reads GET /audit with the given query and decodes the batch.
func getAudit(t *testing.T, c *http.Client, query string) xrayapi.AuditBatch {
	t.Helper()
	resp, err := c.Get("http://xray" + AuditPath + query)
	if err != nil {
		t.Fatalf("GET %s%s: %v", AuditPath, query, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s%s: status %d", AuditPath, query, resp.StatusCode)
	}
	var b xrayapi.AuditBatch
	if err := json.NewDecoder(resp.Body).Decode(&b); err != nil {
		t.Fatalf("decode %s: %v", AuditPath, err)
	}
	return b
}

// postAuditCtl sends POST /audit/ctl {enabled}.
func postAuditCtl(t *testing.T, c *http.Client, enabled bool) {
	t.Helper()
	body, err := json.Marshal(xrayapi.AuditCtlRequest{Enabled: enabled})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Post("http://xray"+AuditCtlPath, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", AuditCtlPath, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST %s: status %d", AuditCtlPath, resp.StatusCode)
	}
}

// accessMessage builds an accepted access message of the shape Xray records:
// "from <src> accepted <to> [<detour>] email: <email>".
func accessMessage(status xlog.AccessStatus, email string) *xlog.AccessMessage {
	return &xlog.AccessMessage{
		From:   "1.2.3.4:5555",
		To:     "tcp:example.com:443",
		Status: status,
		Detour: "node12@machine3 -> direct",
		Email:  email,
	}
}

// TestAuditCollectsAcceptedAccessLines: an accepted access message lands in the
// buffer with its line and a millisecond timestamp; the detour and the email
// are part of the line.
func TestAuditCollectsAcceptedAccessLines(t *testing.T) {
	dir := t.TempDir()
	svc, srv := startAuditService(t, dir)
	defer svc.Close()
	defer srv.Close()
	client := auditClient(srv)
	defer client.CloseIdleConnections()

	postAuditCtl(t, client, true)
	before := time.Now().UnixMilli()
	xlog.Record(accessMessage(xlog.AccessAccepted, "node12@machine3|456"))
	after := time.Now().UnixMilli()

	b := getAudit(t, client, "")
	if len(b.Items) != 1 {
		t.Fatalf("items = %d, want 1 (%+v)", len(b.Items), b)
	}
	if b.FromSeq != 1 || b.ToSeq != 1 {
		t.Errorf("from_seq=%d to_seq=%d, want 1/1", b.FromSeq, b.ToSeq)
	}
	if b.Epoch == 0 {
		t.Errorf("epoch = 0, want the kernel start time")
	}
	if b.More {
		t.Errorf("more = true with a single buffered entry")
	}
	if b.Dropped != 0 {
		t.Errorf("dropped = %d, want 0", b.Dropped)
	}
	item := b.Items[0]
	if item.T < before || item.T > after {
		t.Errorf("t = %d, want within [%d,%d]", item.T, before, after)
	}
	for _, want := range []string{"1.2.3.4:5555", "accepted", "tcp:example.com:443", "node12@machine3 -> direct", "email: node12@machine3|456"} {
		if !strings.Contains(item.L, want) {
			t.Errorf("line %q does not contain %q", item.L, want)
		}
	}
}

// TestAuditIgnoresRejectedAndOtherMessages: only accepted access messages are
// collected; a rejected one and a general message are forwarded but not stored.
func TestAuditIgnoresRejectedAndOtherMessages(t *testing.T) {
	dir := t.TempDir()
	svc, srv := startAuditService(t, dir)
	defer svc.Close()
	defer srv.Close()
	client := auditClient(srv)
	defer client.CloseIdleConnections()

	postAuditCtl(t, client, true)
	xlog.Record(accessMessage(xlog.AccessRejected, "node12@machine3|456"))
	xlog.Record(&xlog.GeneralMessage{Severity: xlog.Severity_Info, Content: "not an access line"})
	xlog.Record(accessMessage(xlog.AccessAccepted, "node12@machine3|456"))

	b := getAudit(t, client, "")
	if len(b.Items) != 1 {
		t.Fatalf("items = %+v, want only the accepted line", b.Items)
	}
	if !strings.Contains(b.Items[0].L, "accepted") {
		t.Errorf("line = %q, want the accepted one", b.Items[0].L)
	}
}

// TestAuditLineWithoutEmail: an access message without an email is collected
// too (the machine has no user identity for it).
func TestAuditLineWithoutEmail(t *testing.T) {
	dir := t.TempDir()
	svc, srv := startAuditService(t, dir)
	defer svc.Close()
	defer srv.Close()
	client := auditClient(srv)
	defer client.CloseIdleConnections()

	postAuditCtl(t, client, true)
	xlog.Record(accessMessage(xlog.AccessAccepted, ""))

	b := getAudit(t, client, "")
	if len(b.Items) != 1 {
		t.Fatalf("items = %d, want 1", len(b.Items))
	}
	if strings.Contains(b.Items[0].L, "email:") {
		t.Errorf("line = %q, want no email part", b.Items[0].L)
	}
}

// TestAuditDisabledCollectsNothing: collection is off by default, so an access
// message is forwarded but nothing is buffered until /audit/ctl turns it on.
func TestAuditDisabledCollectsNothing(t *testing.T) {
	dir := t.TempDir()
	svc, srv := startAuditService(t, dir)
	defer svc.Close()
	defer srv.Close()
	client := auditClient(srv)
	defer client.CloseIdleConnections()

	if svc.AuditEnabled() {
		t.Fatal("collection is on before /audit/ctl")
	}
	xlog.Record(accessMessage(xlog.AccessAccepted, "node12@machine3|456"))
	if b := getAudit(t, client, ""); len(b.Items) != 0 {
		t.Fatalf("items = %+v, want none while collection is off", b.Items)
	}
	if !getStatus(t, srv).Audit {
		t.Error("status.audit = false, want true (the kernel supports audit regardless of the switch)")
	}
}

// TestAuditCtlSwitchesAndClears: turning collection off empties the buffer, so
// a later enable starts a fresh page and the sequence keeps increasing.
func TestAuditCtlSwitchesAndClears(t *testing.T) {
	dir := t.TempDir()
	svc, srv := startAuditService(t, dir)
	defer svc.Close()
	defer srv.Close()
	client := auditClient(srv)
	defer client.CloseIdleConnections()

	postAuditCtl(t, client, true)
	xlog.Record(accessMessage(xlog.AccessAccepted, "node12@machine3|456"))
	if b := getAudit(t, client, ""); len(b.Items) != 1 || b.ToSeq != 1 {
		t.Fatalf("after enable: %+v, want one item with to_seq 1", b)
	}

	postAuditCtl(t, client, false)
	if svc.AuditEnabled() {
		t.Fatal("collection is still on after the off switch")
	}
	if b := getAudit(t, client, ""); len(b.Items) != 0 {
		t.Fatalf("items = %+v, want an empty buffer after the off switch", b.Items)
	}
	// A caller holding the old cursor is told what it missed, not served from
	// the new page as if nothing happened.
	if b := getAudit(t, client, "?after=0"); len(b.Items) != 0 || b.Dropped != 0 {
		t.Fatalf("empty batch after the off switch = %+v, want no items and no gap", b)
	}
	// Off: a recorded message is not collected.
	xlog.Record(accessMessage(xlog.AccessAccepted, "node12@machine3|456"))
	if b := getAudit(t, client, ""); len(b.Items) != 0 {
		t.Fatalf("items = %+v, want none while off", b.Items)
	}

	postAuditCtl(t, client, true)
	xlog.Record(accessMessage(xlog.AccessAccepted, "node12@machine3|456"))
	b := getAudit(t, client, "")
	if len(b.Items) != 1 {
		t.Fatalf("after re-enable: %+v, want one item", b)
	}
	if b.ToSeq != 2 {
		t.Errorf("to_seq = %d, want 2 (sequence numbers never restart)", b.ToSeq)
	}
	// A cursor from before the off switch gets the new entry: the discarded one
	// was reported as the gap of the empty page above, so it is not counted
	// twice.
	stale := getAudit(t, client, "?after=1")
	if len(stale.Items) != 1 || stale.FromSeq != 2 || stale.ToSeq != 2 {
		t.Errorf("stale cursor batch = %+v, want the one new item 2..2", stale)
	}
}

// TestAuditDiscardedEntriesAreCountedOnce: an off switch while a cursor is far
// behind reports the whole gap once, and a cursor inside the gap reports only
// its own remainder.
func TestAuditDiscardedEntriesAreCountedOnce(t *testing.T) {
	c := NewCollector(99)
	c.SetEnabled(true)
	for i := 0; i < 5; i++ {
		c.Append(int64(i), fmt.Sprintf("line %d", i))
	}
	c.SetEnabled(false)
	c.SetEnabled(true)
	for i := 5; i < 8; i++ {
		c.Append(int64(i), fmt.Sprintf("line %d", i))
	}

	fresh := c.Batch(0, 10)
	if len(fresh.Items) != 3 || fresh.FromSeq != 6 || fresh.ToSeq != 8 {
		t.Fatalf("fresh batch = %+v, want items 6..8", fresh)
	}
	if fresh.Dropped != 5 {
		t.Errorf("dropped = %d, want 5 (everything the off switch discarded)", fresh.Dropped)
	}
	// A cursor already past part of the gap reports only what it missed.
	partial := c.Batch(3, 10)
	if partial.FromSeq != 6 || partial.Dropped != 2 {
		t.Errorf("partial batch = %+v, want from_seq 6 and dropped 2", partial)
	}
	// A cursor that never saw the discarded entries (it starts at the floor)
	// reports no gap at all.
	atFloor := c.Batch(5, 10)
	if atFloor.Dropped != 0 || atFloor.FromSeq != 6 {
		t.Errorf("floor cursor batch = %+v, want no gap and from_seq 6", atFloor)
	}
}

// TestAuditCursorAndMore: a page is bounded by max, more reports backlog and
// the cursor returns only what is new.
func TestAuditCursorAndMore(t *testing.T) {
	dir := t.TempDir()
	svc, srv := startAuditService(t, dir)
	defer svc.Close()
	defer srv.Close()
	client := auditClient(srv)
	defer client.CloseIdleConnections()

	postAuditCtl(t, client, true)
	const n = 10
	for i := 0; i < n; i++ {
		xlog.Record(accessMessage(xlog.AccessAccepted, fmt.Sprintf("node12@machine3|%d", i)))
	}

	first := getAudit(t, client, "?max=4")
	if len(first.Items) != 4 || first.FromSeq != 1 || first.ToSeq != 4 {
		t.Fatalf("first page = %+v, want 4 items 1..4", first)
	}
	if !first.More {
		t.Error("more = false with 6 entries still buffered")
	}
	second := getAudit(t, client, fmt.Sprintf("?after=%d&max=4", first.ToSeq))
	if len(second.Items) != 4 || second.FromSeq != 5 || second.ToSeq != 8 {
		t.Fatalf("second page = %+v, want 4 items 5..8", second)
	}
	third := getAudit(t, client, fmt.Sprintf("?after=%d&max=4", second.ToSeq))
	if len(third.Items) != 2 || third.FromSeq != 9 || third.ToSeq != 10 {
		t.Fatalf("third page = %+v, want 2 items 9..10", third)
	}
	if third.More {
		t.Error("more = true after the last buffered entry")
	}
	if !strings.Contains(third.Items[0].L, "|8") || !strings.Contains(third.Items[1].L, "|9") {
		t.Errorf("third page lines = %q, want the last two recorded", []string{third.Items[0].L, third.Items[1].L})
	}
	// Nothing new: an empty page at the current cursor.
	empty := getAudit(t, client, fmt.Sprintf("?after=%d", third.ToSeq))
	if len(empty.Items) != 0 || empty.FromSeq != 0 || empty.ToSeq != 0 || empty.More {
		t.Fatalf("idle page = %+v, want an empty batch", empty)
	}
	// An absurd max is capped at MaxAuditItems, not honoured.
	if huge := getAudit(t, client, "?max=1000000"); len(huge.Items) != n {
		t.Fatalf("max=1000000 returned %d items, want the %d buffered", len(huge.Items), n)
	}
	if len(getAudit(t, client, "?max=0").Items) != n {
		t.Error("max=0 did not fall back to the default page size")
	}
}

// TestAuditOverflowCountsDropped: the ring buffer is bounded, and a cursor from
// before the oldest entry kept is answered from the oldest with the gap in
// dropped.
func TestAuditOverflowCountsDropped(t *testing.T) {
	c := NewCollector(1234)
	c.SetEnabled(true)
	total := auditCapacity + 250
	for i := 0; i < total; i++ {
		c.Append(int64(i), fmt.Sprintf("line %d", i))
	}

	b := c.Batch(0, 10)
	if len(b.Items) != 10 {
		t.Fatalf("items = %d, want 10", len(b.Items))
	}
	wantFrom := uint64(total-auditCapacity) + 1
	if b.FromSeq != wantFrom {
		t.Errorf("from_seq = %d, want %d (the oldest entry kept)", b.FromSeq, wantFrom)
	}
	if b.Dropped != wantFrom-1 {
		t.Errorf("dropped = %d, want %d", b.Dropped, wantFrom-1)
	}
	if b.Epoch != 1234 {
		t.Errorf("epoch = %d, want 1234", b.Epoch)
	}
	if !b.More {
		t.Error("more = false with the whole buffer still buffered")
	}
	// A caller that keeps up never sees dropped again.
	next := c.Batch(b.ToSeq, 10)
	if next.Dropped != 0 {
		t.Errorf("dropped = %d on the next page, want 0", next.Dropped)
	}
	if next.FromSeq != b.ToSeq+1 {
		t.Errorf("from_seq = %d, want %d", next.FromSeq, b.ToSeq+1)
	}
}

// TestAuditTruncatesLongLinesOnUTF8Boundary: a long line is cut to MaxAuditLine
// bytes and the cut never splits a multi-byte rune.
func TestAuditTruncatesLongLinesOnUTF8Boundary(t *testing.T) {
	line := strings.Repeat("中", 400) // 1200 bytes
	got := truncateUTF8(line, xrayapi.MaxAuditLine, &strings.Builder{})
	if len(got) > xrayapi.MaxAuditLine {
		t.Fatalf("len = %d, want at most %d", len(got), xrayapi.MaxAuditLine)
	}
	if !utf8.ValidString(got) {
		t.Fatalf("truncation split a UTF-8 rune: %q", got)
	}
	// MaxAuditLine is not a multiple of 3, so the cut must back off to a
	// boundary: 510 bytes (170 runes).
	if len(got) != 510 {
		t.Errorf("len = %d, want 510 (the last whole rune that fits)", len(got))
	}
	if short := truncateUTF8("short", xrayapi.MaxAuditLine, &strings.Builder{}); short != "short" {
		t.Errorf("a short line changed: %q", short)
	}
	// The collector stores the truncated line.
	c := NewCollector(1)
	c.SetEnabled(true)
	c.Append(7, got)
	if b := c.Batch(0, 1); len(b.Items) != 1 || b.Items[0].L != got {
		t.Fatalf("batch = %+v, want the truncated line", b)
	}
}

// TestAuditTeeKeepsAccessAndErrorOutput: enabling collection does not change
// what the original logger writes. The same message is recorded with the
// collector off and on, and both must appear in the access log.
func TestAuditTeeKeepsAccessAndErrorOutput(t *testing.T) {
	dir := t.TempDir()
	svc, srv := startAuditService(t, dir)
	defer svc.Close()
	defer srv.Close()
	client := auditClient(srv)
	defer client.CloseIdleConnections()

	accessPath := filepath.Join(dir, "access.log")
	readLog := func() string {
		b, err := os.ReadFile(accessPath)
		if err != nil {
			t.Fatalf("read %s: %v", accessPath, err)
		}
		return string(b)
	}
	waitLog := func(want string) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for {
			if strings.Contains(readLog(), want) {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("%q never reached %s: %q", want, accessPath, readLog())
			}
			time.Sleep(20 * time.Millisecond)
		}
	}

	// Off: the instance's own app/log handler writes the access log.
	xlog.Record(accessMessage(xlog.AccessAccepted, "off@machine3|1"))
	waitLog("off@machine3|1")

	// On: the collector's handler replaces it and must keep writing the very
	// same file.
	postAuditCtl(t, client, true)
	xlog.Record(accessMessage(xlog.AccessAccepted, "on@machine3|2"))
	waitLog("on@machine3|2")

	// The replacement logger writes the same shape of line.
	for _, want := range []string{"from 1.2.3.4:5555 accepted tcp:example.com:443", "[node12@machine3 -> direct]", "email: on@machine3|2"} {
		if !strings.Contains(readLog(), want) {
			t.Errorf("access log %q does not contain %q", readLog(), want)
		}
	}
	if b := getAudit(t, client, ""); len(b.Items) != 1 || !strings.Contains(b.Items[0].L, "on@machine3|2") {
		t.Errorf("batch = %+v, want only the line recorded while on", b)
	}
}

// TestAuditHandlerSurvivesReload: an xray instance rebuild replaces the
// instance and its app/log handler; the collector's handler must be reinstalled
// with the switch still on.
func TestAuditHandlerSurvivesReload(t *testing.T) {
	dir := t.TempDir()
	svc, srv := startAuditService(t, dir)
	defer svc.Close()
	defer srv.Close()
	client := auditClient(srv)
	defer client.CloseIdleConnections()

	postAuditCtl(t, client, true)
	xlog.Record(accessMessage(xlog.AccessAccepted, "before@machine3|1"))
	if b := getAudit(t, client, ""); len(b.Items) != 1 {
		t.Fatalf("before the reload: %+v, want one item", b)
	}

	svc.mu.Lock()
	oldCore := svc.core
	svc.mu.Unlock()
	svc.requestReload("test: audit handler reinstall")
	waitCoreChanged(t, svc, oldCore)

	if !svc.AuditEnabled() {
		t.Fatal("the switch was lost across the rebuild")
	}
	xlog.Record(accessMessage(xlog.AccessAccepted, "after@machine3|2"))
	deadline := time.Now().Add(10 * time.Second)
	for {
		b := getAudit(t, client, "?after=1")
		if len(b.Items) == 1 && strings.Contains(b.Items[0].L, "after@machine3|2") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the handler was not reinstalled after the rebuild: %+v", getAudit(t, client, "?after=1"))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestAuditEndpointsRejectOtherMethods: both routes are read/switch only, the
// same way /status is.
func TestAuditEndpointsRejectOtherMethods(t *testing.T) {
	dir := t.TempDir()
	svc, srv := startAuditService(t, dir)
	defer svc.Close()
	defer srv.Close()
	client := auditClient(srv)
	defer client.CloseIdleConnections()

	resp, err := client.Post("http://xray"+AuditPath, "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("POST %s: %v", AuditPath, err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST %s: status %d, want %d", AuditPath, resp.StatusCode, http.StatusMethodNotAllowed)
	}
	resp, err = client.Get("http://xray" + AuditCtlPath)
	if err != nil {
		t.Fatalf("GET %s: %v", AuditCtlPath, err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET %s: status %d, want %d", AuditCtlPath, resp.StatusCode, http.StatusMethodNotAllowed)
	}
}

// TestAuditHandlerIsInstalledAfterStart is the ordering requirement: the
// handler is registered only once the instance is up, so it is the handler xray
// actually uses. app/log registers its own handler while the instance is being
// created, which is why an earlier install would be overwritten — the proof
// that the ordering is right is that a recorded message reaches the collector.
func TestAuditHandlerIsInstalledAfterStart(t *testing.T) {
	dir := t.TempDir()
	svc, srv := startAuditService(t, dir)
	defer svc.Close()
	defer srv.Close()
	client := auditClient(srv)
	defer client.CloseIdleConnections()

	svc.mu.Lock()
	h := svc.auditHandler
	svc.mu.Unlock()
	if h == nil {
		t.Fatal("no audit handler was installed")
	}

	postAuditCtl(t, client, true)
	xlog.Record(accessMessage(xlog.AccessAccepted, "installed@machine3|1"))
	if b := getAudit(t, client, ""); len(b.Items) != 1 {
		t.Fatalf("the audit handler is not the one xray uses: %+v", b)
	}
}

// TestAuditBatchSizeIsBounded: a page never exceeds MaxAuditItems, whatever the
// caller asks for.
func TestAuditBatchSizeIsBounded(t *testing.T) {
	c := NewCollector(1)
	c.SetEnabled(true)
	for i := 0; i < xrayapi.MaxAuditItems+50; i++ {
		c.Append(int64(i), fmt.Sprintf("line %d", i))
	}
	if b := c.Batch(0, 1<<20); len(b.Items) != xrayapi.MaxAuditItems {
		t.Fatalf("items = %d, want the cap %d", len(b.Items), xrayapi.MaxAuditItems)
	}
	if b := c.Batch(0, 0); len(b.Items) != xrayapi.MaxAuditItems {
		t.Fatalf("items = %d with max 0, want the default %d", len(b.Items), xrayapi.MaxAuditItems)
	}
	if b := c.Batch(0, 7); len(b.Items) != 7 {
		t.Fatalf("items = %d with max 7, want 7", len(b.Items))
	}
}

// BenchmarkCollectorAppendDisabled and BenchmarkCollectorAppendEnabled measure
// the two collector paths: the default (off) one must be about an atomic read,
// the on one pays for the copy into the ring.
func BenchmarkCollectorAppendDisabled(b *testing.B) {
	c := NewCollector(1)
	for i := 0; i < b.N; i++ {
		c.Append(int64(i), "from 1.2.3.4:5555 accepted tcp:example.com:443 email: node12@machine3|456")
	}
}

func BenchmarkCollectorAppendEnabled(b *testing.B) {
	c := NewCollector(1)
	c.SetEnabled(true)
	for i := 0; i < b.N; i++ {
		c.Append(int64(i), "from 1.2.3.4:5555 accepted tcp:example.com:443 email: node12@machine3|456")
	}
}
