package bootstrap

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/agentcfg"
	"github.com/W1nCwC/W1nCray/agent/fileops"
	"github.com/W1nCwC/W1nCray/agent/panelclient"
	"github.com/W1nCwC/W1nCray/agent/terminal"
	"github.com/W1nCwC/W1nCray/agent/wsproto"
)

// recordingEvents captures the event frames a terminal audit event becomes.
type recordingEvents struct {
	kinds    []string
	levels   []string
	messages []string
}

func (r *recordingEvents) SendEvent(kind, level, message string) {
	r.kinds = append(r.kinds, kind)
	r.levels = append(r.levels, level)
	r.messages = append(r.messages, message)
}

// TestTerminalManagerIsBuiltOnlyWhenUsable covers WP-G6 acceptance 3 from the
// wiring side: the local switch and the platform probe decide whether the
// manager exists, and the manager's existence is exactly what the capability
// list follows.
func TestTerminalManagerIsBuiltOnlyWhenUsable(t *testing.T) {
	log := nopLog{}

	// The local switch off: no manager, whatever the platform can do.
	if m := newTerminalManager(terminal.Options{Enabled: false}, log); m != nil {
		t.Error("a disabled terminal produced a manager")
	}
	// The local switch on: the manager exists exactly when the platform has a
	// PTY, so a Windows machine and a kernel without /dev/ptmx both get nil.
	m := newTerminalManager(terminal.Options{Enabled: true, Shell: terminal.DefaultShell}, log)
	if terminal.Supported() {
		if m == nil {
			t.Fatal("a supported platform did not produce a manager")
		}
		if !m.Available() {
			t.Error("the manager reports itself unavailable")
		}
		if m.Options().MaxSessions != terminal.DefaultMaxSessions {
			t.Errorf("MaxSessions = %d, want the default %d", m.Options().MaxSessions, terminal.DefaultMaxSessions)
		}
		if m.Options().IdleTimeout != terminal.DefaultIdleTimeout {
			t.Errorf("IdleTimeout = %s, want the default %s", m.Options().IdleTimeout, terminal.DefaultIdleTimeout)
		}
		if m.Options().MaxLifetime != terminal.DefaultMaxLifetime {
			t.Errorf("MaxLifetime = %s, want the default %s", m.Options().MaxLifetime, terminal.DefaultMaxLifetime)
		}
		m.CloseAll(terminal.ReasonAgentShutdown)
	} else {
		if m != nil {
			t.Error("a platform without a PTY produced a manager")
		}
		t.Log("no PTY on this platform: the terminal manager is correctly absent (the Linux test machine exercises the enabled path)")
	}
}

// TestTerminalCapabilityFollowsTheManager keeps the promise rule honest for the
// terminal: the capability is declared exactly when a live manager exists.
func TestTerminalCapabilityFollowsTheManager(t *testing.T) {
	if !terminal.Supported() {
		t.Skip("no PTY on this platform: the enabled-terminal capability is exercised on Linux")
	}
	dir := t.TempDir()
	rt, err := Boot(Options{
		StateDir:   filepath.Join(dir, "state"),
		KernelsDir: filepath.Join(dir, "kernels"),
		Terminal:   terminal.Options{Enabled: true, Shell: terminal.DefaultShell},
	})
	if err != nil {
		t.Fatalf("Boot: %v", err)
	}
	defer func() { _ = rt.Shutdown(context.Background()) }()

	if rt.Terminal == nil {
		t.Fatal("Boot did not build the terminal manager")
	}
	if !hasCapability(rt.Streams(nil, &agentcfg.Config{}).Capabilities(), wsproto.CapTerminal) {
		t.Error("the terminal capability is missing while the manager is live")
	}
	// The policy reports the local gate verbatim.
	if pol := rt.Streams(nil, &agentcfg.Config{}).Policy(); !pol.Terminal {
		t.Errorf("policy.terminal = false, want true: %+v", pol)
	}
}

// TestTerminalDisabledKeepsTheCapabilityOut covers the opt-out path: a machine
// with Terminal.Enabled=false has no manager, no capability and reports the
// local gate as off.
func TestTerminalDisabledKeepsTheCapabilityOut(t *testing.T) {
	dir := t.TempDir()
	rt, err := Boot(Options{
		StateDir:   filepath.Join(dir, "state"),
		KernelsDir: filepath.Join(dir, "kernels"),
		Terminal:   terminal.Options{Enabled: false},
	})
	if err != nil {
		t.Fatalf("Boot: %v", err)
	}
	defer func() { _ = rt.Shutdown(context.Background()) }()

	if rt.Terminal != nil {
		t.Fatal("a disabled terminal produced a manager")
	}
	if rt.TerminalSupported() {
		t.Error("TerminalSupported() is true with the local switch off")
	}
	caps := rt.Streams(nil, &agentcfg.Config{Terminal: &agentcfg.TerminalConfig{Enabled: boolPtr(false)}}).Capabilities()
	if hasCapability(caps, wsproto.CapTerminal) {
		t.Errorf("capabilities = %v, want no terminal", caps)
	}
	if pol := rt.Streams(nil, &agentcfg.Config{Terminal: &agentcfg.TerminalConfig{Enabled: boolPtr(false)}}).Policy(); pol.Terminal {
		t.Errorf("policy.terminal = true with the local switch off: %+v", pol)
	}
}

// TestFilesCapabilityFollowsTheRoots covers the file half: no roots, no
// commands, no capability. With roots the file_* commands exist; the single
// contract capability "files" is declared only once the managed-file layer
// (desired.files, D4/D5) is wired on top of them, because the panel gates that
// desired key on this one name (protocol ruling 1, see filesCapable).
func TestFilesCapabilityFollowsTheRoots(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "xray")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}

	// Without roots.
	rt, err := Boot(Options{StateDir: filepath.Join(dir, "state"), KernelsDir: filepath.Join(dir, "kernels")})
	if err != nil {
		t.Fatalf("Boot: %v", err)
	}
	if rt.FileOps != nil || rt.fileCmdsCapable() || rt.filesCapable() {
		t.Error("a runtime without roots has a file manager")
	}
	if hasCapability(rt.Streams(nil, &agentcfg.Config{}).Capabilities(), wsproto.CapFiles) {
		t.Error("the files capability is declared without roots")
	}
	for _, typ := range []string{panelclient.CmdFileList, panelclient.CmdFileRead, panelclient.CmdFileWrite, panelclient.CmdFileDelete} {
		if rt.Ops.Has(typ) {
			t.Errorf("%s is registered without roots", typ)
		}
	}
	_ = rt.Shutdown(context.Background())

	// With a root: the confined file manager exists and its commands are
	// registered. The managed-file layer is not configured here, so the
	// "files" capability is still withheld (it is the promise the panel gates
	// desired.files on).
	rt2, err := Boot(Options{
		StateDir:   filepath.Join(dir, "state"),
		KernelsDir: filepath.Join(dir, "kernels"),
		FileOps:    fileops.Options{Roots: []fileops.Root{{Name: "xray", Path: root}}},
	})
	if err != nil {
		t.Fatalf("Boot: %v", err)
	}
	defer func() { _ = rt2.Shutdown(context.Background()) }()
	if rt2.FileOps == nil || !rt2.fileCmdsCapable() {
		t.Fatal("a runtime with a root has no file manager")
	}
	if hasCapability(rt2.Streams(nil, &agentcfg.Config{}).Capabilities(), wsproto.CapFiles) {
		t.Error("the files capability is declared without the managed-file layer")
	}
	for _, typ := range []string{panelclient.CmdFileList, panelclient.CmdFileRead, panelclient.CmdFileWrite, panelclient.CmdFileDelete} {
		if !rt2.Ops.Has(typ) {
			t.Errorf("%s is not registered", typ)
		}
	}
	// The file commands really work end to end through the registry.
	status, res := rt2.Ops.Execute(context.Background(), panelclient.Command{
		Type: panelclient.CmdFileWrite,
		Args: json.RawMessage(`{"root":"xray","path":"hello.txt","data":"aGk="}`),
	})
	if status != panelclient.ResultDone {
		t.Fatalf("file_write status = %s, body %s", status, res)
	}
	if b, err := os.ReadFile(filepath.Join(root, "hello.txt")); err != nil || string(b) != "hi" {
		t.Errorf("the file was not written: %q %v", b, err)
	}
	// A path outside the root is refused with the code the panel branches on.
	status, res = rt2.Ops.Execute(context.Background(), panelclient.Command{
		Type: panelclient.CmdFileRead,
		Args: json.RawMessage(`{"root":"xray","path":"../../etc/passwd"}`),
	})
	if status != panelclient.ResultFailed || !strings.Contains(string(res), "invalid_args") {
		t.Errorf("escape read = %s %s", status, res)
	}

	// Both file features wired: the managed-file layer has a root and the
	// separated layout, and the file_* commands have the same root. That is
	// what the single "files" capability promises.
	cfg3 := &agentcfg.Config{Files: &agentcfg.FilesConfig{Roots: []string{root}}}
	rt3, err := Boot(Options{
		StateDir:    filepath.Join(dir, "state3"),
		KernelsDir:  filepath.Join(dir, "kernels"),
		AgentConfig: cfg3,
		Files: &FilesOptions{
			ConfigDir:       root,
			ConfigPath:      filepath.Join(dir, "config.yml"),
			LayoutSeparated: true,
		},
		FileOps: fileops.Options{Roots: []fileops.Root{{Name: "xray", Path: root}}},
	})
	if err != nil {
		t.Fatalf("Boot: %v", err)
	}
	defer func() { _ = rt3.Shutdown(context.Background()) }()
	if !rt3.filesCapable() {
		t.Fatal("filesCapable is false with both file features wired")
	}
	if !hasCapability(rt3.Streams(nil, cfg3).Capabilities(), wsproto.CapFiles) {
		t.Error("the files capability is missing while both file features are live")
	}
}

// TestUnrestrictedFilesWithoutRoots is PLAN v10 requirement 2 at the wiring
// level: a machine with Files.Unrestricted and NO root at all still gets the
// file_* commands and the "files" capability, and the panel addresses it with
// an empty root plus an absolute path.
func TestUnrestrictedFilesWithoutRoots(t *testing.T) {
	dir := t.TempDir()
	cfg := &agentcfg.Config{Files: &agentcfg.FilesConfig{Unrestricted: boolPtr(true)}}
	rt, err := Boot(Options{
		StateDir:    filepath.Join(dir, "state"),
		KernelsDir:  filepath.Join(dir, "kernels"),
		AgentConfig: cfg,
		Files: &FilesOptions{
			ConfigDir:       filepath.Join(dir, "xray"),
			ConfigPath:      filepath.Join(dir, "config.yml"),
			LayoutSeparated: true,
		},
		FileOps: fileops.Options{Unrestricted: boolPtr(true)},
	})
	if err != nil {
		t.Fatalf("Boot: %v", err)
	}
	defer func() { _ = rt.Shutdown(context.Background()) }()
	if rt.FileOps == nil {
		t.Fatal("an unrestricted machine without roots has no file manager")
	}
	if !rt.FileOps.Unrestricted() || len(rt.FileOps.RootNames()) != 0 {
		t.Errorf("FileOps unrestricted=%v roots=%v", rt.FileOps.Unrestricted(), rt.FileOps.RootNames())
	}
	if !rt.fileCmdsCapable() {
		t.Error("the file_* commands are not capable on an unrestricted machine")
	}
	if !rt.filesCapable() {
		t.Error("the files capability is withheld although both file features are live")
	}
	if !hasCapability(rt.Streams(nil, cfg).Capabilities(), wsproto.CapFiles) {
		t.Error("the files capability is missing")
	}
	for _, typ := range []string{
		panelclient.CmdFileList, panelclient.CmdFileRead, panelclient.CmdFileWrite,
		panelclient.CmdFileDelete, panelclient.CmdFileMkdir, panelclient.CmdFileRename,
	} {
		if !rt.Ops.Has(typ) {
			t.Errorf("%s is not registered", typ)
		}
	}
	// The policy reports the effective value and the (defaulted) roots.
	pol := rt.Streams(nil, cfg).Policy()
	if !pol.Files.Unrestricted {
		t.Errorf("policy.files = %+v, want unrestricted", pol.Files)
	}
	// End to end: an empty root and an absolute path.
	target := filepath.Join(dir, "unrestricted.txt")
	status, res := rt.Ops.Execute(context.Background(), panelclient.Command{
		Type: panelclient.CmdFileWrite,
		Args: json.RawMessage(`{"root":"","path":"` + filepath.ToSlash(target) + `","data":"aGk="}`),
	})
	if status != panelclient.ResultDone {
		t.Fatalf("file_write status = %s, body %s", status, res)
	}
	if b, err := os.ReadFile(target); err != nil || string(b) != "hi" {
		t.Errorf("the file was not written: %q %v", b, err)
	}
	// mkdir and rename work the same way, and a relative path is still refused.
	if status, res = rt.Ops.Execute(context.Background(), panelclient.Command{
		Type: panelclient.CmdFileMkdir,
		Args: json.RawMessage(`{"root":"","path":"` + filepath.ToSlash(filepath.Join(dir, "sub")) + `"}`),
	}); status != panelclient.ResultDone {
		t.Fatalf("file_mkdir status = %s, body %s", status, res)
	}
	if status, res = rt.Ops.Execute(context.Background(), panelclient.Command{
		Type: panelclient.CmdFileRename,
		Args: json.RawMessage(`{"root":"","path":"` + filepath.ToSlash(target) + `","to":"` + filepath.ToSlash(filepath.Join(dir, "moved.txt")) + `"}`),
	}); status != panelclient.ResultDone {
		t.Fatalf("file_rename status = %s, body %s", status, res)
	}
	if status, res = rt.Ops.Execute(context.Background(), panelclient.Command{
		Type: panelclient.CmdFileList,
		Args: json.RawMessage(`{"root":"","path":"relative"}`),
	}); status != panelclient.ResultFailed || !strings.Contains(string(res), "invalid_args") {
		t.Errorf("a relative path was accepted: %s %s", status, res)
	}
}

// TestFileRootsAreNamedForThePanel covers the root naming rule: the xray
// configuration directory is "xray", the agent state directory is "state", and
// anything else gets a stable name derived from its directory.
func TestFileRootsAreNamedForThePanel(t *testing.T) {
	xray := filepath.Join(t.TempDir(), "W1nCray")
	state := filepath.Join(xray, "state")
	other := filepath.Join(t.TempDir(), "geo")
	roots := FileRoots([]string{xray, state, other, other}, xray, state)
	if len(roots) != 4 {
		t.Fatalf("roots = %+v", roots)
	}
	if roots[0].Name != "xray" || roots[0].Path != xray {
		t.Errorf("roots[0] = %+v", roots[0])
	}
	if roots[1].Name != "state" || roots[1].Path != state {
		t.Errorf("roots[1] = %+v", roots[1])
	}
	// The repeated directory gets a distinct name instead of shadowing the
	// first entry.
	if roots[2].Name == roots[3].Name {
		t.Errorf("duplicate roots share the name %q", roots[2].Name)
	}
	if roots[2].Name != "geo" {
		t.Errorf("roots[2].Name = %q, want geo", roots[2].Name)
	}
	// A trailing separator must not change the name.
	trailing := FileRoots([]string{xray + string(filepath.Separator)}, xray, state)
	if trailing[0].Name != "xray" {
		t.Errorf("a trailing separator changed the name: %+v", trailing)
	}
}

// TestTerminalAuditorReportsMetadataOnly covers WP-G6 acceptance 6 at the
// wiring level: the event frame carries the metadata (session, action,
// duration, byte counts, reason) and nothing else.
func TestTerminalAuditorReportsMetadataOnly(t *testing.T) {
	events := &recordingEvents{}
	a := terminalAuditor{events: events, log: nopLog{}}
	a.TerminalEvent(terminal.AuditEvent{
		Session:   "sess-1",
		Action:    "close",
		DurationS: 42,
		BytesIn:   7,
		BytesOut:  1024,
		Reason:    terminal.ReasonIdleTimeout,
	})
	if len(events.kinds) != 1 || events.kinds[0] != terminalEventKind {
		t.Fatalf("events = %+v", events)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(events.messages[0]), &payload); err != nil {
		t.Fatalf("message %q is not JSON: %v", events.messages[0], err)
	}
	for _, key := range []string{"session", "action", "at", "duration_s", "bytes_in", "bytes_out", "reason"} {
		if _, ok := payload[key]; !ok {
			t.Errorf("the audit payload has no %q: %s", key, events.messages[0])
		}
	}
	// The byte counts are numbers, not content; there is no field that could
	// hold terminal bytes.
	if payload["bytes_in"].(float64) != 7 || payload["bytes_out"].(float64) != 1024 {
		t.Errorf("byte counts = %v / %v", payload["bytes_in"], payload["bytes_out"])
	}
	if payload["reason"] != terminal.ReasonIdleTimeout {
		t.Errorf("reason = %v", payload["reason"])
	}
	// A session reclaimed by a deadline is reported at warn level.
	if events.levels[0] != "warn" {
		t.Errorf("level = %q, want warn for a deadline reclaim", events.levels[0])
	}
	// A normal exit stays at info.
	events.kinds, events.levels, events.messages = nil, nil, nil
	a.TerminalEvent(terminal.AuditEvent{Session: "s", Action: "close", Reason: terminal.ReasonExit})
	if events.levels[0] != "info" {
		t.Errorf("level = %q, want info for a normal exit", events.levels[0])
	}
}

// TestTerminalAuditorWithoutASinkIsInert keeps a nil event sink from panicking
// (the HTTP-only agent has no event channel).
func TestTerminalAuditorWithoutASinkIsInert(t *testing.T) {
	a := terminalAuditor{log: nopLog{}}
	a.TerminalEvent(terminal.AuditEvent{Session: "s", Action: "open"})
}

// TestWSTerminalAdapter covers the sink the WebSocket dispatcher calls: the
// size is validated, an unknown session is refused and a live one is addressed.
func TestWSTerminalAdapter(t *testing.T) {
	if !terminal.Supported() {
		t.Skip("no PTY on this platform: the adapter's live-session path runs on Linux")
	}
	dir := t.TempDir()
	rt, err := Boot(Options{
		StateDir:   filepath.Join(dir, "state"),
		KernelsDir: filepath.Join(dir, "kernels"),
		Terminal:   terminal.Options{Enabled: true, Shell: terminal.DefaultShell},
	})
	if err != nil {
		t.Fatalf("Boot: %v", err)
	}
	defer func() { _ = rt.Shutdown(context.Background()) }()

	adapter := wsTerminal{m: rt.Terminal}
	if err := adapter.Open("s1", 0, 0); err == nil {
		t.Error("a zero size was accepted")
	}
	if err := adapter.Open("s1", 1001, 24); err == nil {
		t.Error("an oversized size was accepted")
	}
	if err := adapter.Open("s1", 80, 24); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, ok := rt.Terminal.Get("s1"); !ok {
		t.Fatal("the session was not created")
	}
	if err := adapter.Input("nope", []byte("x")); err != terminal.ErrNotFound {
		t.Errorf("Input of an unknown session = %v", err)
	}
	if err := adapter.Resize("s1", 120, 40); err != nil {
		t.Errorf("Resize: %v", err)
	}
	if err := adapter.Resize("s1", 0, 40); err == nil {
		t.Error("Resize with a zero size was accepted")
	}
	if err := adapter.Close("s1"); err != nil {
		t.Errorf("Close: %v", err)
	}
	// Close is asynchronous: the session leaves the registry once its child has
	// exited, and closing it again before that is an idempotent no-op.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := rt.Terminal.Get("s1"); !ok {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := adapter.Close("s1"); err != terminal.ErrNotFound {
		t.Errorf("Close of a closed session = %v, want ErrNotFound", err)
	}
}

// TestBootShutdownClosesTheTerminal covers WP-G6 acceptance 4 from the wiring
// side: Shutdown runs CloseAll, so the agent never leaves a session behind.
func TestBootShutdownClosesTheTerminal(t *testing.T) {
	if !terminal.Supported() {
		t.Skip("no PTY on this platform: the live-session shutdown check runs on Linux")
	}
	dir := t.TempDir()
	rt, err := Boot(Options{
		StateDir:   filepath.Join(dir, "state"),
		KernelsDir: filepath.Join(dir, "kernels"),
		Terminal:   terminal.Options{Enabled: true, Shell: terminal.DefaultShell},
	})
	if err != nil {
		t.Fatalf("Boot: %v", err)
	}
	if _, err := rt.Terminal.Open("live", 80, 24); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := rt.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if got := rt.Terminal.Sessions(); len(got) != 0 {
		t.Errorf("sessions after Shutdown = %v", got)
	}
}
