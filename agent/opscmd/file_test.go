package opscmd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/W1nCwC/W1nCray/agent/fileops"
	"github.com/W1nCwC/W1nCray/agent/panelclient"
)

// fakeFileCmds is the FileCmdOps surface with no disk behind it. The confinement
// rules themselves are covered by agent/fileops's table-driven tests; here the
// command layer is what is under test: argument decoding, base64, size limits
// and the error codes the panel branches on.
type fakeFileCmds struct {
	entries   []fileops.Entry
	read      fileops.ReadResult
	write     fileops.WriteResult
	listErr   error
	readErr   error
	writeErr  error
	deleteErr error

	gotRoot   string
	gotPath   string
	gotOffset int64
	gotLimit  int64
	gotData   []byte
	gotMode   os.FileMode
	gotSHA    string
	deleted   []string
	maxRead   int64
	maxWrite  int64
	roots     []string
}

func (f *fakeFileCmds) List(ctx context.Context, root, path string) ([]fileops.Entry, error) {
	f.gotRoot, f.gotPath = root, path
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.entries, nil
}

func (f *fakeFileCmds) Read(ctx context.Context, root, path string, offset, limit int64) (fileops.ReadResult, error) {
	f.gotRoot, f.gotPath, f.gotOffset, f.gotLimit = root, path, offset, limit
	if f.readErr != nil {
		return fileops.ReadResult{}, f.readErr
	}
	return f.read, nil
}

func (f *fakeFileCmds) Write(ctx context.Context, root, path string, data []byte, mode os.FileMode, wantSHA string) (fileops.WriteResult, error) {
	f.gotRoot, f.gotPath, f.gotData, f.gotMode, f.gotSHA = root, path, data, mode, wantSHA
	if f.writeErr != nil {
		return fileops.WriteResult{}, f.writeErr
	}
	return f.write, nil
}

func (f *fakeFileCmds) Delete(ctx context.Context, root, path string) error {
	f.deleted = append(f.deleted, root+":"+path)
	if f.deleteErr != nil {
		return f.deleteErr
	}
	return nil
}

func (f *fakeFileCmds) RootNames() []string {
	if f.roots == nil {
		return []string{"xray", "state"}
	}
	return f.roots
}
func (f *fakeFileCmds) MaxRead() int64  { return orDefault(f.maxRead, fileops.DefaultMaxRead) }
func (f *fakeFileCmds) MaxWrite() int64 { return orDefault(f.maxWrite, fileops.DefaultMaxWrite) }
func (f *fakeFileCmds) Unrestricted() bool {
	return false
}

func orDefault(v, def int64) int64 {
	if v <= 0 {
		return def
	}
	return v
}

// filesRegistry builds a registry with the file commands registered.
func filesRegistry(t *testing.T, files FileCmdOps) *Registry {
	t.Helper()
	r := mustRegistry(t, Deps{})
	if err := RegisterFileCmds(r, files); err != nil {
		t.Fatalf("RegisterFileCmds: %v", err)
	}
	return r
}

// TestRegisterFileCmdsNeedsRoots covers the promise rule: a machine without a
// configured root must not expose the file commands at all.
func TestRegisterFileCmdsNeedsRoots(t *testing.T) {
	r := mustRegistry(t, Deps{})
	if err := RegisterFileCmds(r, nil); err == nil {
		t.Error("RegisterFileCmds(nil) succeeded")
	}
	if err := RegisterFileCmds(r, &fakeFileCmds{roots: []string{}}); err == nil {
		t.Error("RegisterFileCmds without roots succeeded")
	}
	if r.Has(panelclient.CmdFileList) {
		t.Error("file_list is registered after a refused RegisterFileCmds")
	}
	if err := RegisterFileCmds(r, &fakeFileCmds{}); err != nil {
		t.Fatalf("RegisterFileCmds with roots: %v", err)
	}
	for _, typ := range []string{panelclient.CmdFileList, panelclient.CmdFileRead, panelclient.CmdFileWrite, panelclient.CmdFileDelete} {
		if !r.Has(typ) {
			t.Errorf("%s is not registered", typ)
		}
	}
}

// TestFileListDecodesAndReports covers file_list: the default path is the root,
// the configured roots travel with the answer, and a refused path carries the
// machine-readable code.
func TestFileListDecodesAndReports(t *testing.T) {
	files := &fakeFileCmds{entries: []fileops.Entry{{Name: "config.yml", Type: "file", Size: 12, Mode: "0644", MTime: 1700000000}}}
	r := filesRegistry(t, files)

	status, res := r.Execute(context.Background(), panelclient.Command{Type: panelclient.CmdFileList, Args: json.RawMessage(`{"root":"xray"}`)})
	if status != StatusDone {
		t.Fatalf("status = %s, body %s", status, res)
	}
	if files.gotRoot != "xray" || files.gotPath != "." {
		t.Errorf("List(%q, %q), want (xray, .)", files.gotRoot, files.gotPath)
	}
	var out fileListResult
	if err := json.Unmarshal(res, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Entries) != 1 || out.Entries[0].Name != "config.yml" || out.Entries[0].Type != "file" {
		t.Errorf("entries = %+v", out.Entries)
	}
	if len(out.Roots) != 2 || out.Roots[0] != "xray" {
		t.Errorf("roots = %v", out.Roots)
	}

	// A refused path is failed with a stable code.
	files.listErr = fileops.ErrOutsideRoots
	status, res = r.Execute(context.Background(), panelclient.Command{Type: panelclient.CmdFileList, Args: json.RawMessage(`{"root":"xray","path":"../x"}`)})
	if status != StatusFailed {
		t.Fatalf("status = %s", status)
	}
	if f := decodeFailure(t, res); f.Code != "outside_roots" {
		t.Errorf("code = %q, want outside_roots (%s)", f.Code, res)
	}

	// Unknown fields are refused (protocol drift is caught, not ignored).
	status, res = r.Execute(context.Background(), panelclient.Command{Type: panelclient.CmdFileList, Args: json.RawMessage(`{"root":"xray","nope":1}`)})
	if status != StatusFailed {
		t.Fatalf("an unknown field was accepted: %s", res)
	}
	if f := decodeFailure(t, res); f.Code != "invalid_args" {
		t.Errorf("code = %q, want invalid_args", f.Code)
	}
}

// TestFileReadBase64AndLimits covers file_read: the data is base64 on the wire,
// the offset/limit reach the manager, and a limit over the local maximum is
// refused before any read.
func TestFileReadBase64AndLimits(t *testing.T) {
	files := &fakeFileCmds{read: fileops.ReadResult{Data: []byte("hello"), Size: 5, EOF: true}}
	r := filesRegistry(t, files)

	status, res := r.Execute(context.Background(), panelclient.Command{
		Type: panelclient.CmdFileRead,
		Args: json.RawMessage(`{"root":"xray","path":"config.yml","offset":3,"limit":10}`),
	})
	if status != StatusDone {
		t.Fatalf("status = %s, body %s", status, res)
	}
	if files.gotOffset != 3 || files.gotLimit != 10 {
		t.Errorf("Read offset=%d limit=%d", files.gotOffset, files.gotLimit)
	}
	var out fileReadResult
	if err := json.Unmarshal(res, &out); err != nil {
		t.Fatal(err)
	}
	if out.Data != base64.StdEncoding.EncodeToString([]byte("hello")) || out.Size != 5 || !out.EOF {
		t.Errorf("read result = %+v", out)
	}

	// Over the local limit: refused with too_large, and the manager is not
	// asked to read anything.
	files.gotLimit = -1
	status, res = r.Execute(context.Background(), panelclient.Command{
		Type: panelclient.CmdFileRead,
		Args: json.RawMessage(`{"root":"xray","path":"config.yml","limit":999999}`),
	})
	if status != StatusFailed {
		t.Fatalf("status = %s", status)
	}
	if f := decodeFailure(t, res); f.Code != "too_large" {
		t.Errorf("code = %q, want too_large", f.Code)
	}
	if files.gotLimit != -1 {
		t.Error("the manager was called despite the limit being refused")
	}

	// A negative offset is refused.
	status, res = r.Execute(context.Background(), panelclient.Command{
		Type: panelclient.CmdFileRead,
		Args: json.RawMessage(`{"root":"xray","path":"config.yml","offset":-1}`),
	})
	if status != StatusFailed {
		t.Fatalf("a negative offset was accepted: %s", res)
	}
}

// TestFileWriteBase64HashAndMode covers file_write: the payload is decoded from
// base64, the sha256 travels through, the mode is parsed, and an oversized or
// malformed payload is refused before it reaches the manager.
func TestFileWriteBase64HashAndMode(t *testing.T) {
	files := &fakeFileCmds{write: fileops.WriteResult{Path: "/srv/xray/a.txt", SHA256: "abc", Size: 5, Created: true}}
	r := filesRegistry(t, files)

	body := base64.StdEncoding.EncodeToString([]byte("hello"))
	status, res := r.Execute(context.Background(), panelclient.Command{
		Type: panelclient.CmdFileWrite,
		Args: json.RawMessage(`{"root":"xray","path":"a.txt","data":"` + body + `","mode":"0600","sha256":"deadbeef"}`),
	})
	if status != StatusDone {
		t.Fatalf("status = %s, body %s", status, res)
	}
	if string(files.gotData) != "hello" {
		t.Errorf("data = %q", files.gotData)
	}
	if files.gotMode != 0o600 {
		t.Errorf("mode = %04o, want 0600", files.gotMode)
	}
	if files.gotSHA != "deadbeef" {
		t.Errorf("sha256 = %q", files.gotSHA)
	}
	var out fileops.WriteResult
	if err := json.Unmarshal(res, &out); err != nil {
		t.Fatal(err)
	}
	if !out.Created || out.Size != 5 {
		t.Errorf("write result = %+v", out)
	}

	// An empty mode means the manager's default.
	files.gotMode = 0
	if status, res = r.Execute(context.Background(), panelclient.Command{
		Type: panelclient.CmdFileWrite,
		Args: json.RawMessage(`{"root":"xray","path":"a.txt","data":"` + body + `"}`),
	}); status != StatusDone {
		t.Fatalf("status = %s, body %s", status, res)
	}
	if files.gotMode != 0 {
		t.Errorf("mode = %04o, want the zero value (manager default)", files.gotMode)
	}

	// Bad base64.
	status, res = r.Execute(context.Background(), panelclient.Command{
		Type: panelclient.CmdFileWrite,
		Args: json.RawMessage(`{"root":"xray","path":"a.txt","data":"not base64!!"}`),
	})
	if status != StatusFailed {
		t.Fatalf("bad base64 was accepted: %s", res)
	}
	if f := decodeFailure(t, res); f.Code != "invalid_args" {
		t.Errorf("code = %q, want invalid_args", f.Code)
	}

	// Over MaxWrite: refused with too_large and nothing written.
	files.gotData = nil
	big := base64.StdEncoding.EncodeToString(make([]byte, fileops.DefaultMaxWrite+1))
	status, res = r.Execute(context.Background(), panelclient.Command{
		Type: panelclient.CmdFileWrite,
		Args: json.RawMessage(`{"root":"xray","path":"a.txt","data":"` + big + `"}`),
	})
	if status != StatusFailed {
		t.Fatalf("an oversized payload was accepted: %s", res)
	}
	if f := decodeFailure(t, res); f.Code != "too_large" {
		t.Errorf("code = %q, want too_large", f.Code)
	}
	if files.gotData != nil {
		t.Error("the manager was called despite the size being refused")
	}

	// A mode that is not octal.
	status, res = r.Execute(context.Background(), panelclient.Command{
		Type: panelclient.CmdFileWrite,
		Args: json.RawMessage(`{"root":"xray","path":"a.txt","data":"` + body + `","mode":"rwxr-xr-x"}`),
	})
	if status != StatusFailed {
		t.Fatalf("a non-octal mode was accepted: %s", res)
	}

	// root/path are required.
	status, res = r.Execute(context.Background(), panelclient.Command{
		Type: panelclient.CmdFileWrite,
		Args: json.RawMessage(`{"data":"` + body + `"}`),
	})
	if status != StatusFailed {
		t.Fatalf("a write without root/path was accepted: %s", res)
	}
}

// TestFileWriteRefusalsCarryCodes covers the mapping from fileops sentinels to
// the codes the panel branches on.
func TestFileWriteRefusalsCarryCodes(t *testing.T) {
	cases := []struct {
		err  error
		code string
	}{
		{fileops.ErrSymlink, "symlink"},
		{fileops.ErrNotRegular, "not_regular"},
		{fileops.ErrIsDir, "is_a_directory"},
		{fileops.ErrExecBit, "exec_bit"},
		{fileops.ErrSpecialMode, "special_mode"},
		{fileops.ErrHashMismatch, "sha256_mismatch"},
		{fileops.ErrUnknownRoot, "unknown_root"},
		{fileops.ErrTooLarge, "too_large"},
		{fileops.ErrBadPath, "invalid_args"},
		{fileops.ErrOutsideRoots, "outside_roots"},
	}
	body := base64.StdEncoding.EncodeToString([]byte("x"))
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			files := &fakeFileCmds{writeErr: tc.err}
			r := filesRegistry(t, files)
			status, res := r.Execute(context.Background(), panelclient.Command{
				Type: panelclient.CmdFileWrite,
				Args: json.RawMessage(`{"root":"xray","path":"a.txt","data":"` + body + `"}`),
			})
			if status != StatusFailed {
				t.Fatalf("status = %s", status)
			}
			if f := decodeFailure(t, res); f.Code != tc.code {
				t.Errorf("code = %q, want %q", f.Code, tc.code)
			}
		})
	}
}

// TestFileDeleteRequiresRootAndPath covers file_delete's argument rules and the
// not_regular mapping (a directory delete).
func TestFileDeleteRequiresRootAndPath(t *testing.T) {
	files := &fakeFileCmds{}
	r := filesRegistry(t, files)

	if status, res := r.Execute(context.Background(), panelclient.Command{
		Type: panelclient.CmdFileDelete,
		Args: json.RawMessage(`{"root":"xray","path":"old.yml"}`),
	}); status != StatusDone {
		t.Fatalf("status = %s, body %s", status, res)
	}
	if len(files.deleted) != 1 || files.deleted[0] != "xray:old.yml" {
		t.Errorf("deleted = %v", files.deleted)
	}

	files.deleteErr = fileops.ErrIsDir
	status, res := r.Execute(context.Background(), panelclient.Command{
		Type: panelclient.CmdFileDelete,
		Args: json.RawMessage(`{"root":"xray","path":"sub"}`),
	})
	if status != StatusFailed {
		t.Fatalf("status = %s", status)
	}
	if f := decodeFailure(t, res); f.Code != "is_a_directory" {
		t.Errorf("code = %q, want is_a_directory", f.Code)
	}

	if status, _ = r.Execute(context.Background(), panelclient.Command{
		Type: panelclient.CmdFileDelete,
		Args: json.RawMessage(`{"path":"x"}`),
	}); status != StatusFailed {
		t.Error("a delete without a root was accepted")
	}
}

// TestFileCommandsWithoutAManagerAnswerNotSupported covers a registry built
// without the file manager: the types are unknown, so the answer is the
// historical "unsupported command" failure, never an execution.
func TestFileCommandsWithoutAManagerAnswerNotSupported(t *testing.T) {
	r := mustRegistry(t, Deps{})
	for _, typ := range []string{panelclient.CmdFileList, panelclient.CmdFileRead, panelclient.CmdFileWrite, panelclient.CmdFileDelete} {
		if r.Has(typ) {
			t.Errorf("%s is registered without a manager", typ)
		}
		status, res := r.Execute(context.Background(), panelclient.Command{Type: typ})
		if status != StatusFailed {
			t.Errorf("%s status = %s", typ, status)
		}
		if f := decodeFailure(t, res); !strings.Contains(f.Error, "unsupported command") {
			t.Errorf("%s error = %q", typ, f.Error)
		}
	}
}

// TestParseFileMode covers the mode string parser directly.
func TestParseFileMode(t *testing.T) {
	cases := []struct {
		in   string
		want os.FileMode
		bad  bool
	}{
		{"", 0, false},
		{"0644", 0o644, false},
		{"600", 0o600, false},
		{"0755", 0o755, false},
		{"4755", 0o4755, false}, // parsed here; fileops refuses the setuid bit
		{"9999", 0, true},
		{"rw-r--r--", 0, true},
	}
	for _, tc := range cases {
		got, err := parseFileMode(tc.in)
		if tc.bad {
			if err == nil {
				t.Errorf("parseFileMode(%q) = %04o, want an error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseFileMode(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseFileMode(%q) = %04o, want %04o", tc.in, got, tc.want)
		}
	}
}

// TestFileErrPassesUnknownErrorsThrough keeps the mapping honest: an error
// without a code stays a plain failure (the panel then shows the text).
func TestFileErrPassesUnknownErrorsThrough(t *testing.T) {
	plain := errors.New("disk on fire")
	if got := fileErr(plain); got != plain {
		t.Errorf("fileErr(%v) = %v", plain, got)
	}
	if got := codeOf(fileErr(plain)); got != "" {
		t.Errorf("code = %q, want empty", got)
	}
	if fileErr(nil) != nil {
		t.Error("fileErr(nil) != nil")
	}
}
