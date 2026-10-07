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
	appendRes fileops.WriteResult
	mkdirRes  fileops.MkdirResult
	renameRes fileops.RenameResult
	listErr   error
	readErr   error
	writeErr  error
	appendErr error
	deleteErr error
	mkdirErr  error
	renameErr error

	gotRoot    string
	gotPath    string
	gotOffset  int64
	gotLimit   int64
	gotData    []byte
	gotMode    os.FileMode
	gotSHA     string
	gotAppend  bool
	gotTo      string
	deleted    []string
	maxRead    int64
	maxWrite   int64
	roots      []string
	unrestrict bool
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
	f.gotAppend = false
	if f.writeErr != nil {
		return fileops.WriteResult{}, f.writeErr
	}
	return f.write, nil
}

func (f *fakeFileCmds) Append(ctx context.Context, root, path string, data []byte, wantSHA string) (fileops.WriteResult, error) {
	f.gotRoot, f.gotPath, f.gotData, f.gotSHA = root, path, data, wantSHA
	f.gotAppend = true
	if f.appendErr != nil {
		return fileops.WriteResult{}, f.appendErr
	}
	return f.appendRes, nil
}

func (f *fakeFileCmds) Delete(ctx context.Context, root, path string) error {
	f.deleted = append(f.deleted, root+":"+path)
	if f.deleteErr != nil {
		return f.deleteErr
	}
	return nil
}

func (f *fakeFileCmds) Mkdir(ctx context.Context, root, path string, mode os.FileMode) (fileops.MkdirResult, error) {
	f.gotRoot, f.gotPath, f.gotMode = root, path, mode
	if f.mkdirErr != nil {
		return fileops.MkdirResult{}, f.mkdirErr
	}
	return f.mkdirRes, nil
}

func (f *fakeFileCmds) Rename(ctx context.Context, root, path, to string) (fileops.RenameResult, error) {
	f.gotRoot, f.gotPath, f.gotTo = root, path, to
	if f.renameErr != nil {
		return fileops.RenameResult{}, f.renameErr
	}
	return f.renameRes, nil
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
	return f.unrestrict
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

// TestRegisterFileCmdsNeedsRoots covers the promise rule: a machine that can
// serve nothing (no root and not unrestricted) must not expose the file
// commands at all. An unrestricted machine needs no root: the panel names
// absolute paths with an empty root (PLAN v10).
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
	for _, typ := range []string{
		panelclient.CmdFileList, panelclient.CmdFileRead, panelclient.CmdFileWrite,
		panelclient.CmdFileDelete, panelclient.CmdFileMkdir, panelclient.CmdFileRename,
	} {
		if !r.Has(typ) {
			t.Errorf("%s is not registered", typ)
		}
	}
	// Rootless but unrestricted: the commands exist.
	ur := mustRegistry(t, Deps{})
	if err := RegisterFileCmds(ur, &fakeFileCmds{roots: []string{}, unrestrict: true}); err != nil {
		t.Fatalf("RegisterFileCmds(unrestricted, no roots): %v", err)
	}
	if !ur.Has(panelclient.CmdFileList) || !ur.Has(panelclient.CmdFileRename) {
		t.Error("the file commands are missing on an unrestricted machine without roots")
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
		{fileops.ErrExists, "already_exists"},
		{fileops.ErrNotExist, "not_found"},
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
	for _, typ := range []string{
		panelclient.CmdFileList, panelclient.CmdFileRead, panelclient.CmdFileWrite,
		panelclient.CmdFileDelete, panelclient.CmdFileMkdir, panelclient.CmdFileRename,
	} {
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

// TestFileWriteAppend covers file_write with append=true: the payload reaches
// Append (not Write), no mode is applied, and the whole-file digest comes back.
func TestFileWriteAppend(t *testing.T) {
	files := &fakeFileCmds{appendRes: fileops.WriteResult{Path: "/srv/xray/big.bin", SHA256: "ff", Size: 300, Append: true}}
	r := filesRegistry(t, files)
	body := base64.StdEncoding.EncodeToString([]byte("chunk"))

	status, res := r.Execute(context.Background(), panelclient.Command{
		Type: panelclient.CmdFileWrite,
		Args: json.RawMessage(`{"root":"xray","path":"big.bin","data":"` + body + `","append":true,"sha256":"deadbeef"}`),
	})
	if status != StatusDone {
		t.Fatalf("status = %s, body %s", status, res)
	}
	if !files.gotAppend || string(files.gotData) != "chunk" || files.gotSHA != "deadbeef" {
		t.Errorf("Append(%q, %q, %q) append=%v", files.gotRoot, files.gotPath, files.gotData, files.gotAppend)
	}
	var out fileops.WriteResult
	if err := json.Unmarshal(res, &out); err != nil {
		t.Fatal(err)
	}
	if !out.Append || out.Size != 300 || out.SHA256 != "ff" {
		t.Errorf("result = %+v, want the whole-file size and sha256", out)
	}

	// A refused append carries the code the panel branches on.
	files.appendErr = fileops.ErrNotExist
	status, res = r.Execute(context.Background(), panelclient.Command{
		Type: panelclient.CmdFileWrite,
		Args: json.RawMessage(`{"root":"xray","path":"gone.bin","data":"` + body + `","append":true}`),
	})
	if status != StatusFailed {
		t.Fatalf("status = %s", status)
	}
	if f := decodeFailure(t, res); f.Code != "not_found" {
		t.Errorf("code = %q, want not_found", f.Code)
	}

	// The size limit applies to the chunk.
	big := base64.StdEncoding.EncodeToString(make([]byte, fileops.DefaultMaxWrite+1))
	if status, res = r.Execute(context.Background(), panelclient.Command{
		Type: panelclient.CmdFileWrite,
		Args: json.RawMessage(`{"root":"xray","path":"big.bin","data":"` + big + `","append":true}`),
	}); status != StatusFailed {
		t.Fatalf("an oversized append was accepted: %s", res)
	}
}

// TestFileMkdirCommand covers file_mkdir: the args decode strictly, the mode is
// the same octal string as file_write, and the outcome is reported.
func TestFileMkdirCommand(t *testing.T) {
	files := &fakeFileCmds{mkdirRes: fileops.MkdirResult{Path: "/srv/xray/a/b", Created: true}}
	r := filesRegistry(t, files)

	status, res := r.Execute(context.Background(), panelclient.Command{
		Type: panelclient.CmdFileMkdir,
		Args: json.RawMessage(`{"root":"xray","path":"a/b","mode":"0700"}`),
	})
	if status != StatusDone {
		t.Fatalf("status = %s, body %s", status, res)
	}
	if files.gotRoot != "xray" || files.gotPath != "a/b" || files.gotMode != 0o700 {
		t.Errorf("Mkdir(%q, %q, %04o)", files.gotRoot, files.gotPath, files.gotMode)
	}
	var out fileops.MkdirResult
	if err := json.Unmarshal(res, &out); err != nil {
		t.Fatal(err)
	}
	if !out.Created || out.Path != "/srv/xray/a/b" {
		t.Errorf("result = %+v", out)
	}

	// An omitted mode is the manager's default (0 = 0755 in fileops).
	files.gotMode = 1
	if status, res = r.Execute(context.Background(), panelclient.Command{
		Type: panelclient.CmdFileMkdir,
		Args: json.RawMessage(`{"root":"xray","path":"a/b"}`),
	}); status != StatusDone {
		t.Fatalf("status = %s, body %s", status, res)
	}
	if files.gotMode != 0 {
		t.Errorf("mode = %04o, want the zero value (manager default)", files.gotMode)
	}

	// Unknown fields, a missing path and a non-octal mode are refused.
	for _, args := range []string{
		`{"root":"xray","path":"a","nope":1}`,
		`{"root":"xray"}`,
		`{"root":"xray","path":"a","mode":"rwx"}`,
	} {
		if status, res = r.Execute(context.Background(), panelclient.Command{Type: panelclient.CmdFileMkdir, Args: json.RawMessage(args)}); status != StatusFailed {
			t.Errorf("mkdir %s was accepted: %s", args, res)
		}
	}
	// A missing root is refused on a confined machine.
	if status, _ = r.Execute(context.Background(), panelclient.Command{
		Type: panelclient.CmdFileMkdir,
		Args: json.RawMessage(`{"path":"a"}`),
	}); status != StatusFailed {
		t.Error("mkdir without a root was accepted on a confined machine")
	}
}

// TestFileRenameCommand covers file_rename: both paths travel to the manager,
// a missing to is refused before it, and an existing target is reported.
func TestFileRenameCommand(t *testing.T) {
	files := &fakeFileCmds{renameRes: fileops.RenameResult{Path: "/srv/xray/a", To: "/srv/xray/b", Renamed: true}}
	r := filesRegistry(t, files)

	status, res := r.Execute(context.Background(), panelclient.Command{
		Type: panelclient.CmdFileRename,
		Args: json.RawMessage(`{"root":"xray","path":"a","to":"b"}`),
	})
	if status != StatusDone {
		t.Fatalf("status = %s, body %s", status, res)
	}
	if files.gotRoot != "xray" || files.gotPath != "a" || files.gotTo != "b" {
		t.Errorf("Rename(%q, %q, %q)", files.gotRoot, files.gotPath, files.gotTo)
	}
	var out fileops.RenameResult
	if err := json.Unmarshal(res, &out); err != nil {
		t.Fatal(err)
	}
	if !out.Renamed || out.To != "/srv/xray/b" {
		t.Errorf("result = %+v", out)
	}

	// to is required.
	if status, res = r.Execute(context.Background(), panelclient.Command{
		Type: panelclient.CmdFileRename,
		Args: json.RawMessage(`{"root":"xray","path":"a"}`),
	}); status != StatusFailed {
		t.Fatalf("a rename without to was accepted: %s", res)
	}
	if f := decodeFailure(t, res); f.Code != "invalid_args" {
		t.Errorf("code = %q, want invalid_args", f.Code)
	}

	// The existing-target refusal keeps its own code.
	files.renameErr = fileops.ErrExists
	status, res = r.Execute(context.Background(), panelclient.Command{
		Type: panelclient.CmdFileRename,
		Args: json.RawMessage(`{"root":"xray","path":"a","to":"b"}`),
	})
	if status != StatusFailed {
		t.Fatalf("status = %s", status)
	}
	if f := decodeFailure(t, res); f.Code != "already_exists" {
		t.Errorf("code = %q, want already_exists", f.Code)
	}
}

// TestFileCommandsUnrestrictedRootConvention pins PLAN v10's argument
// convention: on an unrestricted machine the panel sends an EMPTY root and an
// absolute path, and the handlers accept it for every file command.
func TestFileCommandsUnrestrictedRootConvention(t *testing.T) {
	files := &fakeFileCmds{roots: []string{}, unrestrict: true, entries: []fileops.Entry{{Name: "etc"}}}
	r := filesRegistry(t, files)
	body := base64.StdEncoding.EncodeToString([]byte("x"))
	ctx := context.Background()

	for _, tc := range []struct {
		typ  string
		args string
	}{
		{panelclient.CmdFileList, `{"path":"/etc"}`},
		{panelclient.CmdFileRead, `{"path":"/etc/hosts"}`},
		{panelclient.CmdFileWrite, `{"path":"/etc/hosts","data":"` + body + `"}`},
		{panelclient.CmdFileDelete, `{"path":"/etc/hosts"}`},
		{panelclient.CmdFileMkdir, `{"path":"/etc/w1ncray"}`},
		{panelclient.CmdFileRename, `{"path":"/etc/a","to":"/etc/b"}`},
	} {
		if status, res := r.Execute(ctx, panelclient.Command{Type: tc.typ, Args: json.RawMessage(tc.args)}); status != StatusDone {
			t.Errorf("%s %s: status = %s, body %s", tc.typ, tc.args, status, res)
		}
		if files.gotRoot != "" {
			t.Errorf("%s sent root %q to the manager", tc.typ, files.gotRoot)
		}
	}
	// A relative path is passed through unchanged: refusing it is fileops's job
	// (the command layer only enforces the shape of the arguments).
	r.Execute(ctx, panelclient.Command{
		Type: panelclient.CmdFileList,
		Args: json.RawMessage(`{"path":"etc"}`),
	})
	if files.gotPath != "etc" {
		t.Errorf("path = %q, want etc", files.gotPath)
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
