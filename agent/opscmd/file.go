// This file registers the file_* commands (file_list, file_read, file_write,
// file_delete, file_mkdir, file_rename). It only decodes the arguments and maps
// the outcome onto the wire: the confinement rules live in agent/fileops, which
// every command goes through (design section 3.9).
//
// Root argument convention (PLAN v10): a confined machine sends a root name and
// a relative path; an unrestricted machine sends an EMPTY root and an absolute
// path (Ops.Resolve ignores the root there). Both shapes are accepted by the
// handlers, so one panel code path works on either kind of machine.

package opscmd

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"

	"github.com/W1nCwC/W1nCray/agent/fileops"
	"github.com/W1nCwC/W1nCray/agent/panelclient"
)

// FileCmdOps is the confined file manager the file_* commands need. It is
// declared here so this package does not import a concrete implementation and
// so tests can substitute a fake.
//
// It is NOT the managed-file surface (FilesOps, files_apply and friends): the
// two features only share the "files" capability name in the contract, and
// their implementations (agent/fileops vs agent/filesync) are unrelated.
type FileCmdOps interface {
	List(ctx context.Context, root, path string) ([]fileops.Entry, error)
	Read(ctx context.Context, root, path string, offset, limit int64) (fileops.ReadResult, error)
	Write(ctx context.Context, root, path string, data []byte, mode os.FileMode, wantSHA string) (fileops.WriteResult, error)
	// Append adds one bounded chunk to an existing file (file_write with
	// append=true); the result describes the whole file after the append.
	Append(ctx context.Context, root, path string, data []byte, wantSHA string) (fileops.WriteResult, error)
	Delete(ctx context.Context, root, path string) error
	// Mkdir creates path (and missing parents) like mkdir -p.
	Mkdir(ctx context.Context, root, path string, mode os.FileMode) (fileops.MkdirResult, error)
	// Rename moves path to to inside the same root and never overwrites.
	Rename(ctx context.Context, root, path, to string) (fileops.RenameResult, error)
	// RootNames lists the configured roots; the panel needs them to know what
	// it may name. It is empty on an unrestricted machine (the panel sends an
	// empty root and an absolute path).
	RootNames() []string
	// MaxRead and MaxWrite are the local size limits.
	MaxRead() int64
	MaxWrite() int64
	// Unrestricted reports the effective Files.Unrestricted switch: the root
	// lookup is skipped and paths are absolute.
	Unrestricted() bool
}

// fileCmds holds the dependencies of the file handlers.
type fileCmds struct {
	reg  *Registry
	deps Deps
}

// registerFileCmds adds the file_* commands. It is called by bootstrap once the
// local policy has been resolved; a machine with neither a root nor
// Files.Unrestricted simply never registers them (the commands then answer
// "unsupported command", and the "files" capability is not declared either).
func registerFileCmds(r *Registry, d Deps) error {
	f := &fileCmds{reg: r, deps: d}
	for _, c := range []struct {
		typ string
		h   Handler
	}{
		{panelclient.CmdFileList, f.fileList},
		{panelclient.CmdFileRead, f.fileRead},
		{panelclient.CmdFileWrite, f.fileWrite},
		{panelclient.CmdFileDelete, f.fileDelete},
		{panelclient.CmdFileMkdir, f.fileMkdir},
		{panelclient.CmdFileRename, f.fileRename},
	} {
		if err := r.Register(c.typ, c.h); err != nil {
			return err
		}
	}
	return nil
}

// RegisterFileCmds is the additive hook bootstrap calls to make the file_*
// commands exist. It refuses a nil manager and a manager that could serve
// nothing: a machine with no root AND without Files.Unrestricted would offer a
// feature it cannot use (protocol ruling 1). An unrestricted machine needs no
// root at all — the panel names absolute paths. It is separate from the
// managed-file commands (files_apply and friends), which New registers itself.
func RegisterFileCmds(r *Registry, ops FileCmdOps) error {
	if r == nil {
		return errors.New("opscmd: nil registry")
	}
	if ops == nil {
		return errors.New("opscmd: nil file operations")
	}
	if len(ops.RootNames()) == 0 && !ops.Unrestricted() {
		return errors.New("opscmd: the file commands need at least one configured root (or Files.Unrestricted)")
	}
	return registerFileCmds(r, Deps{FileCmds: ops, Log: r.logf()})
}

// ---- args ------------------------------------------------------------------

// fileListArgs is the args of file_list. A missing path means the root itself.
type fileListArgs struct {
	Root string `json:"root"`
	Path string `json:"path"`
}

// fileReadArgs is the args of file_read.
type fileReadArgs struct {
	Root   string `json:"root"`
	Path   string `json:"path"`
	Offset int64  `json:"offset,omitempty"`
	Limit  int64  `json:"limit,omitempty"`
}

// fileWriteArgs is the args of file_write. Data is base64 on the wire; append
// adds it to the end of an existing file instead of replacing it.
type fileWriteArgs struct {
	Root   string `json:"root"`
	Path   string `json:"path"`
	Data   string `json:"data"`
	Mode   string `json:"mode,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	Append bool   `json:"append,omitempty"`
}

// fileDeleteArgs is the args of file_delete.
type fileDeleteArgs struct {
	Root string `json:"root"`
	Path string `json:"path"`
}

// fileMkdirArgs is the args of file_mkdir. Mode is the octal string file_write
// uses; the default is 0755.
type fileMkdirArgs struct {
	Root string `json:"root"`
	Path string `json:"path"`
	Mode string `json:"mode,omitempty"`
}

// fileRenameArgs is the args of file_rename. To names the target inside the
// same root (an absolute path on an unrestricted machine).
type fileRenameArgs struct {
	Root string `json:"root"`
	Path string `json:"path"`
	To   string `json:"to"`
}

// fileListResult is the result of file_list.
type fileListResult struct {
	Entries []fileops.Entry `json:"entries"`
	Roots   []string        `json:"roots"`
}

// fileReadResult is the result of file_read (data is base64).
type fileReadResult struct {
	Data string `json:"data"`
	Size int64  `json:"size"`
	EOF  bool   `json:"eof"`
}

// fileDeleteResult is the result of file_delete.
type fileDeleteResult struct {
	Path    string `json:"path"`
	Deleted bool   `json:"deleted"`
}

// ---- handlers --------------------------------------------------------------

func (f *fileCmds) ops() (FileCmdOps, error) {
	if f.deps.FileCmds == nil {
		return nil, coded("not_supported", errors.New("file operations are not wired on this agent"))
	}
	return f.deps.FileCmds, nil
}

func (f *fileCmds) fileList(ctx context.Context, req Request, complete Completion) (Result, error) {
	var a fileListArgs
	if err := decodeArgs(req.Args, &a); err != nil {
		return Result{}, err
	}
	ops, err := f.ops()
	if err != nil {
		return Result{}, err
	}
	if a.Path == "" {
		a.Path = "."
	}
	if err := checkRootArg(ops, a.Root, a.Path); err != nil {
		return Result{}, err
	}
	entries, err := ops.List(ctx, a.Root, a.Path)
	if err != nil {
		return Result{}, fileErr(err)
	}
	return done(fileListResult{Entries: entries, Roots: ops.RootNames()}), nil
}

func (f *fileCmds) fileRead(ctx context.Context, req Request, complete Completion) (Result, error) {
	var a fileReadArgs
	if err := decodeArgs(req.Args, &a); err != nil {
		return Result{}, err
	}
	ops, err := f.ops()
	if err != nil {
		return Result{}, err
	}
	if a.Limit < 0 || a.Offset < 0 {
		return Result{}, coded("invalid_args", errors.New("offset and limit must not be negative"))
	}
	if err := checkRootArg(ops, a.Root, a.Path); err != nil {
		return Result{}, err
	}
	// The contract caps a read at 128 KiB raw; the local limit may be lower.
	if a.Limit > ops.MaxRead() {
		return Result{}, coded("too_large", fmt.Errorf("limit %d exceeds the local maximum %d", a.Limit, ops.MaxRead()))
	}
	res, err := ops.Read(ctx, a.Root, a.Path, a.Offset, a.Limit)
	if err != nil {
		return Result{}, fileErr(err)
	}
	return done(fileReadResult{
		Data: base64.StdEncoding.EncodeToString(res.Data),
		Size: res.Size,
		EOF:  res.EOF,
	}), nil
}

func (f *fileCmds) fileWrite(ctx context.Context, req Request, complete Completion) (Result, error) {
	var a fileWriteArgs
	if err := decodeArgs(req.Args, &a); err != nil {
		return Result{}, err
	}
	ops, err := f.ops()
	if err != nil {
		return Result{}, err
	}
	if err := checkRootArg(ops, a.Root, a.Path); err != nil {
		return Result{}, err
	}
	// base64 first: a payload whose decoded size exceeds the limit is refused
	// before the bytes are materialised a second time.
	data, err := base64.StdEncoding.DecodeString(a.Data)
	if err != nil {
		return Result{}, coded("invalid_args", fmt.Errorf("data is not valid base64: %w", err))
	}
	if int64(len(data)) > ops.MaxWrite() {
		return Result{}, coded("too_large", fmt.Errorf("%d bytes exceeds the local maximum %d", len(data), ops.MaxWrite()))
	}
	if a.Append {
		// An append never changes the mode (the file exists already), so a
		// mode argument is not decoded at all: sending one is not an error,
		// it is simply not applicable.
		res, err := ops.Append(ctx, a.Root, a.Path, data, a.SHA256)
		if err != nil {
			return Result{}, fileErr(err)
		}
		return done(res), nil
	}
	mode, err := parseFileMode(a.Mode)
	if err != nil {
		return Result{}, err
	}
	res, err := ops.Write(ctx, a.Root, a.Path, data, mode, a.SHA256)
	if err != nil {
		return Result{}, fileErr(err)
	}
	return done(res), nil
}

func (f *fileCmds) fileDelete(ctx context.Context, req Request, complete Completion) (Result, error) {
	var a fileDeleteArgs
	if err := decodeArgs(req.Args, &a); err != nil {
		return Result{}, err
	}
	ops, err := f.ops()
	if err != nil {
		return Result{}, err
	}
	if err := checkRootArg(ops, a.Root, a.Path); err != nil {
		return Result{}, err
	}
	if err := ops.Delete(ctx, a.Root, a.Path); err != nil {
		return Result{}, fileErr(err)
	}
	return done(fileDeleteResult{Path: a.Path, Deleted: true}), nil
}

func (f *fileCmds) fileMkdir(ctx context.Context, req Request, complete Completion) (Result, error) {
	var a fileMkdirArgs
	if err := decodeArgs(req.Args, &a); err != nil {
		return Result{}, err
	}
	ops, err := f.ops()
	if err != nil {
		return Result{}, err
	}
	if err := checkRootArg(ops, a.Root, a.Path); err != nil {
		return Result{}, err
	}
	mode, err := parseFileMode(a.Mode)
	if err != nil {
		return Result{}, err
	}
	res, err := ops.Mkdir(ctx, a.Root, a.Path, mode)
	if err != nil {
		return Result{}, fileErr(err)
	}
	return done(res), nil
}

func (f *fileCmds) fileRename(ctx context.Context, req Request, complete Completion) (Result, error) {
	var a fileRenameArgs
	if err := decodeArgs(req.Args, &a); err != nil {
		return Result{}, err
	}
	ops, err := f.ops()
	if err != nil {
		return Result{}, err
	}
	if err := checkRootArg(ops, a.Root, a.Path); err != nil {
		return Result{}, err
	}
	if a.To == "" {
		return Result{}, coded("invalid_args", errors.New("to is required"))
	}
	res, err := ops.Rename(ctx, a.Root, a.Path, a.To)
	if err != nil {
		return Result{}, fileErr(err)
	}
	return done(res), nil
}

// ---- helpers ---------------------------------------------------------------

// checkRootArg enforces the root/path shape of every file command. path is
// always required. root is required only on a confined machine: an
// unrestricted machine is addressed with an empty root and an absolute path
// (PLAN v10), so demanding a root there would make the whole feature unusable.
func checkRootArg(ops FileCmdOps, root, path string) error {
	if path == "" {
		return coded("invalid_args", errors.New("path is required"))
	}
	if root == "" && !ops.Unrestricted() {
		return coded("invalid_args", errors.New("root is required (this machine is not unrestricted)"))
	}
	return nil
}

// parseFileMode decodes the contract's mode string ("0644", "600", ...). An
// empty string means the default (0644), which fileops applies. The permission
// policy (no setuid, exec bit needs Files.AllowExec) is fileops's job, so this
// only rejects what is not an octal number at all.
func parseFileMode(s string) (os.FileMode, error) {
	if s == "" {
		return 0, nil
	}
	var mode uint32
	if _, err := fmt.Sscanf(s, "%o", &mode); err != nil {
		return 0, coded("invalid_args", fmt.Errorf("mode %q is not an octal file mode", s))
	}
	if mode > 0o7777 {
		return 0, coded("invalid_args", fmt.Errorf("mode %q is out of range", s))
	}
	return os.FileMode(mode), nil
}

// fileErr attaches a stable machine-readable code to a fileops error, so the
// panel can branch on the reason instead of parsing prose.
func fileErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, fileops.ErrOutsideRoots):
		return coded("outside_roots", err)
	case errors.Is(err, fileops.ErrSymlink):
		return coded("symlink", err)
	case errors.Is(err, fileops.ErrNotRegular):
		return coded("not_regular", err)
	case errors.Is(err, fileops.ErrNotDir):
		return coded("not_a_directory", err)
	case errors.Is(err, fileops.ErrIsDir):
		return coded("is_a_directory", err)
	case errors.Is(err, fileops.ErrTooLarge):
		return coded("too_large", err)
	case errors.Is(err, fileops.ErrExecBit):
		return coded("exec_bit", err)
	case errors.Is(err, fileops.ErrSpecialMode):
		return coded("special_mode", err)
	case errors.Is(err, fileops.ErrHashMismatch):
		return coded("sha256_mismatch", err)
	case errors.Is(err, fileops.ErrExists):
		return coded("already_exists", err)
	case errors.Is(err, fileops.ErrNotExist):
		return coded("not_found", err)
	case errors.Is(err, fileops.ErrUnknownRoot):
		return coded("unknown_root", err)
	case errors.Is(err, fileops.ErrNoRoots):
		return coded("not_supported", err)
	case errors.Is(err, fileops.ErrBadPath):
		return coded("invalid_args", err)
	default:
		return err
	}
}
