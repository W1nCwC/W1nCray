package fileops

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/W1nCwC/W1nCray/agent/driver"
)

// testRoots builds a confined layout:
//
//	<tmp>/root/{sub/, secret.txt, sub/inside.txt, link-to-outside, link-to-passwd}
//	<tmp>/outside/evil.txt
//	<tmp>/state/desired.json   (an excluded agent file)
func testRoots(t *testing.T) (root string, o *Ops) {
	t.Helper()
	base := t.TempDir()
	root = filepath.Join(base, "root")
	state := filepath.Join(base, "state")
	for _, d := range []string{filepath.Join(root, "sub"), state, filepath.Join(base, "outside")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(p, s string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(p, []byte(s), mode); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(root, "secret.txt"), "top secret", 0o644)
	write(filepath.Join(root, "sub", "inside.txt"), "inside", 0o600)
	write(filepath.Join(base, "outside", "evil.txt"), "evil", 0o644)
	write(filepath.Join(state, "desired.json"), `{"schema":1}`, 0o600)
	symlinksOK := trySymlink(filepath.Join(base, "outside", "evil.txt"), filepath.Join(root, "link-to-outside")) &&
		trySymlink("/etc/passwd", filepath.Join(root, "link-to-passwd"))
	if !symlinksOK {
		t.Log("this platform refuses a symlink without extra privileges: the symlink rows are exercised on Linux")
	}

	ops, err := New(Options{
		Roots:               []Root{{Name: "xray", Path: root}, {Name: "state", Path: state}},
		Excluded:            []string{filepath.Join(state, "desired.json"), filepath.Join(base, "agent.yml")},
		Log:                 nopLog{},
		testAllowSystemRoot: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return root, ops
}

// TestResolveRootItself covers the "." path: file_list of the root directory.
func TestResolveRootItself(t *testing.T) {
	root, ops := testRoots(t)
	got, err := ops.Resolve("xray", ".")
	if err != nil {
		t.Fatalf("Resolve(xray, .) = %v", err)
	}
	if got != root {
		t.Errorf("Resolve(xray, .) = %q, want %q", got, root)
	}
	entries, err := ops.List(context.Background(), "xray", ".")
	if err != nil {
		t.Fatalf("List(xray, .) = %v", err)
	}
	if len(entries) == 0 {
		t.Error("List of the root directory is empty")
	}
}

// trySymlink creates a symlink and reports whether it worked. Windows refuses
// one without the SeCreateSymbolicLink privilege; the rows that need it skip
// and say why (the Linux test machine exercises them).
func trySymlink(target, link string) bool {
	return os.Symlink(target, link) == nil
}

// linkOrSkip skips the calling test when its symlink could not be created.
func linkOrSkip(t *testing.T, link string) string {
	t.Helper()
	if _, err := os.Lstat(link); err != nil {
		t.Skipf("no symlink at %s (%v): this row runs on Linux", link, err)
	}
	return link
}

// TestResolveRejectsEscapes is the table-driven half of WP-G6 acceptance 7: a
// path that leaves the root, names a symlink, or is absolute is refused, and
// the error identifies why.
func TestResolveRejectsEscapes(t *testing.T) {
	_, ops := testRoots(t)
	cases := []struct {
		name string
		root string
		path string
		want error
	}{
		{"dotdot", "xray", "../../etc/passwd", ErrBadPath},
		{"dotdot-single", "xray", "../outside/evil.txt", ErrBadPath},
		{"dotdot-in-middle", "xray", "sub/../../outside/evil.txt", ErrBadPath},
		{"absolute", "xray", "/etc/passwd", ErrBadPath},
		{"absolute-root", "xray", "/", ErrBadPath},
		{"backslash", "xray", `..\..\etc\passwd`, ErrBadPath},
		{"windows-drive", "xray", `C:\Windows\System32`, ErrBadPath},
		{"empty", "xray", "", ErrBadPath},
		{"nul", "xray", "a\x00b", ErrBadPath},
		{"symlink-to-passwd", "xray", "link-to-passwd", ErrSymlink},
		{"symlink-out-of-root", "xray", "link-to-outside", ErrSymlink},
		{"symlink-in-dir-walk", "xray", "link-to-outside/x", ErrSymlink},
		{"unknown-root", "nope", "secret.txt", ErrUnknownRoot},
		{"excluded-state-file", "state", "desired.json", ErrOutsideRoots},
		{"missing-dir", "xray", "nodir/file.txt", ErrBadPath},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.want == ErrSymlink {
				// The link must exist for the row to mean anything.
				linkOrSkip(t, filepath.Join(ops.Roots()[0].Path, strings.SplitN(tc.path, "/", 2)[0]))
			}
			_, err := ops.Resolve(tc.root, tc.path)
			if err == nil {
				t.Fatalf("Resolve(%q, %q) succeeded; it must be refused", tc.root, tc.path)
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("Resolve(%q, %q) = %v, want %v", tc.root, tc.path, err, tc.want)
			}
		})
	}
}

// TestResolveAcceptsConfinedPaths is the positive half: a normal relative path
// inside a root resolves, including one that does not exist yet.
func TestResolveAcceptsConfinedPaths(t *testing.T) {
	root, ops := testRoots(t)
	for _, rel := range []string{"secret.txt", "sub/inside.txt", "new-file.txt", "sub/new.txt"} {
		got, err := ops.Resolve("xray", rel)
		if err != nil {
			t.Errorf("Resolve(xray, %q) = %v", rel, err)
			continue
		}
		want := filepath.Join(root, filepath.FromSlash(rel))
		if got != want {
			t.Errorf("Resolve(xray, %q) = %q, want %q", rel, got, want)
		}
	}
}

// TestReadRefusesSpecialFiles covers FIFOs and devices: file_read must never
// block on a FIFO nor read a device.
func TestReadRefusesSpecialFiles(t *testing.T) {
	root, ops := testRoots(t)
	ctx := context.Background()

	// A directory is not a regular file.
	if _, err := ops.Read(ctx, "xray", "sub", 0, 0); !errors.Is(err, ErrNotRegular) && !errors.Is(err, ErrNotDir) {
		t.Errorf("Read of a directory = %v, want ErrNotRegular or ErrNotDir", err)
	}
	// A symlink is refused by Resolve before any read.
	if _, err := os.Lstat(filepath.Join(root, "link-to-passwd")); err == nil {
		if _, err := ops.Read(ctx, "xray", "link-to-passwd", 0, 0); !errors.Is(err, ErrSymlink) {
			t.Errorf("Read of a symlink = %v, want ErrSymlink", err)
		}
	} else {
		t.Log("no symlink could be created here: the symlink row runs on Linux")
	}
	// A device node, where the platform lets us make one.
	makeSpecial(t, filepath.Join(root, "fifo"), filepath.Join(root, "device"))
	for _, name := range []string{"fifo", "device"} {
		if _, err := os.Lstat(filepath.Join(root, name)); err != nil {
			continue // not creatable here (Windows, or no permission)
		}
		if _, err := ops.Read(ctx, "xray", name, 0, 0); !errors.Is(err, ErrNotRegular) {
			t.Errorf("Read of %s = %v, want ErrNotRegular", name, err)
		}
		if _, err := ops.Write(ctx, "xray", name, []byte("x"), 0o644, ""); !errors.Is(err, ErrNotRegular) {
			t.Errorf("Write over %s = %v, want ErrNotRegular", name, err)
		}
		if err := ops.Delete(ctx, "xray", name); !errors.Is(err, ErrNotRegular) {
			t.Errorf("Delete of %s = %v, want ErrNotRegular", name, err)
		}
	}
}

// TestReadRefusesDevices covers a real character device, which is always
// present on Unix. The FIFO case is covered by TestReadRefusesSpecialFiles.
func TestReadRefusesDevices(t *testing.T) {
	dev := "/dev/null"
	if _, err := os.Lstat(dev); err != nil {
		t.Skipf("%s is not available: %v", dev, err)
	}
	ops, err := New(Options{Unrestricted: boolPtr(true), testAllowSystemRoot: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := ops.Read(ctx, "", dev, 0, 0); !errors.Is(err, ErrNotRegular) {
		t.Errorf("Read of %s = %v, want ErrNotRegular", dev, err)
	}
	if err := ops.Delete(ctx, "", dev); !errors.Is(err, ErrNotRegular) {
		t.Errorf("Delete of %s = %v, want ErrNotRegular", dev, err)
	}
	if _, err := ops.Write(ctx, "", dev, []byte("x"), 0o644, ""); !errors.Is(err, ErrNotRegular) {
		t.Errorf("Write over %s = %v, want ErrNotRegular", dev, err)
	}
}

// TestDeleteRefusesDirectoriesAndLinks covers acceptance 7's "directory
// deletion" row: one file_delete can never empty a directory tree.
func TestDeleteRefusesDirectoriesAndLinks(t *testing.T) {
	root, ops := testRoots(t)
	ctx := context.Background()
	if err := ops.Delete(ctx, "xray", "sub"); !errors.Is(err, ErrIsDir) {
		t.Errorf("Delete of a directory = %v, want ErrIsDir", err)
	}
	linkOrSkip(t, filepath.Join(ops.Roots()[0].Path, "link-to-passwd"))
	if err := ops.Delete(ctx, "xray", "link-to-passwd"); !errors.Is(err, ErrSymlink) {
		t.Errorf("Delete of a symlink = %v, want ErrSymlink", err)
	}
	if err := ops.Delete(ctx, "xray", "sub/inside.txt"); err != nil {
		t.Errorf("Delete of a regular file: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "sub", "inside.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the file still exists after Delete: %v", err)
	}
	// The directory it lived in is untouched.
	if _, err := os.Stat(filepath.Join(root, "sub")); err != nil {
		t.Errorf("the parent directory was removed: %v", err)
	}
}

// TestWriteSizeAndHash covers acceptance 8's size and sha256 rows.
func TestWriteSizeAndHash(t *testing.T) {
	_, ops := testRoots(t)
	ctx := context.Background()

	good := []byte("hello file")
	sum := sha256.Sum256(good)
	hexSum := hex.EncodeToString(sum[:])

	res, err := ops.Write(ctx, "xray", "hashed.txt", good, 0o644, hexSum)
	if err != nil {
		t.Fatalf("Write with the right sha256: %v", err)
	}
	if res.SHA256 != hexSum {
		t.Errorf("SHA256 = %s, want %s", res.SHA256, hexSum)
	}
	if !res.Created {
		t.Error("Created = false for a new file")
	}
	// Upper case is accepted (the panel may send either).
	if _, err := ops.Write(ctx, "xray", "upper.txt", good, 0o644, strings.ToUpper(hexSum)); err != nil {
		t.Errorf("Write with an upper-case sha256: %v", err)
	}
	// A wrong hash is refused and nothing is written.
	if _, err := ops.Write(ctx, "xray", "bad.txt", good, 0o644, strings.Repeat("0", 64)); !errors.Is(err, ErrHashMismatch) {
		t.Errorf("Write with a wrong sha256 = %v, want ErrHashMismatch", err)
	}
	if _, err := os.Lstat(filepath.Join(ops.Roots()[0].Path, "bad.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a file was written despite the hash mismatch: %v", err)
	}
	// Over MaxWrite is refused.
	big := make([]byte, DefaultMaxWrite+1)
	if _, err := ops.Write(ctx, "xray", "big.bin", big, 0o644, ""); !errors.Is(err, ErrTooLarge) {
		t.Errorf("Write over MaxWrite = %v, want ErrTooLarge", err)
	}
	// Exactly MaxWrite is accepted.
	exact := bytes.Repeat([]byte("a"), int(DefaultMaxWrite))
	if _, err := ops.Write(ctx, "xray", "exact.bin", exact, 0o644, ""); err != nil {
		t.Errorf("Write of exactly MaxWrite bytes: %v", err)
	}
}

// TestWriteIsAtomicAndRefusesSymlinkTargets covers the atomic write and the
// "no write through a symlink" rule.
func TestWriteIsAtomicAndRefusesSymlinkTargets(t *testing.T) {
	root, ops := testRoots(t)
	ctx := context.Background()

	if _, err := ops.Write(ctx, "xray", "new.txt", []byte("v1"), 0o644, ""); err != nil {
		t.Fatal(err)
	}
	res, err := ops.Write(ctx, "xray", "new.txt", []byte("v2"), 0o644, "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Created {
		t.Error("Created = true when overwriting")
	}
	got, err := os.ReadFile(filepath.Join(root, "new.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "v2" {
		t.Errorf("content = %q, want v2", got)
	}
	// No temp file is left behind.
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("a temp file survived the write: %s", e.Name())
		}
	}
	// A symlink target is refused rather than replaced.
	if _, err := os.Lstat(filepath.Join(root, "link-to-outside")); err != nil {
		t.Skip("no symlink could be created here: the symlink-target row runs on Linux")
	}
	if _, err := ops.Write(ctx, "xray", "link-to-outside", []byte("pwn"), 0o644, ""); !errors.Is(err, ErrSymlink) {
		t.Errorf("Write over a symlink = %v, want ErrSymlink", err)
	}
	if got, _ := os.ReadFile(filepath.Join(root, "..", "outside", "evil.txt")); string(got) != "evil" {
		t.Errorf("the symlink target was modified: %q", got)
	}
}

// TestReadOffsetAndLimit covers the read window.
func TestReadOffsetAndLimit(t *testing.T) {
	root, ops := testRoots(t)
	ctx := context.Background()
	if _, err := ops.Write(ctx, "xray", "window.txt", []byte("0123456789"), 0o644, ""); err != nil {
		t.Fatal(err)
	}
	res, err := ops.Read(ctx, "xray", "window.txt", 2, 4)
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Data) != "2345" {
		t.Errorf("data = %q, want 2345", res.Data)
	}
	if res.EOF {
		t.Error("EOF = true before the end of the file")
	}
	res, err = ops.Read(ctx, "xray", "window.txt", 8, 100)
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Data) != "89" || !res.EOF {
		t.Errorf("tail read = %q eof=%v", res.Data, res.EOF)
	}
	// An offset past the end is empty and EOF.
	res, err = ops.Read(ctx, "xray", "window.txt", 100, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Data) != 0 || !res.EOF {
		t.Errorf("read past the end = %q eof=%v", res.Data, res.EOF)
	}
	// A limit over MaxRead is refused.
	if _, err := ops.Read(ctx, "xray", "window.txt", 0, DefaultMaxRead+1); !errors.Is(err, ErrTooLarge) {
		t.Errorf("Read over MaxRead = %v, want ErrTooLarge", err)
	}
	if _, err := ops.Read(ctx, "xray", "window.txt", -1, 10); !errors.Is(err, ErrBadPath) {
		t.Errorf("Read with a negative offset = %v, want ErrBadPath", err)
	}
	_ = root
}

// TestListReportsTypesAndRefusesNonDirectories covers file_list.
func TestListReportsTypesAndRefusesNonDirectories(t *testing.T) {
	_, ops := testRoots(t)
	ctx := context.Background()
	entries, err := ops.List(ctx, "xray", ".")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	byName := map[string]Entry{}
	for _, e := range entries {
		byName[e.Name] = e
	}
	wantTypes := map[string]string{"secret.txt": "file", "sub": "dir"}
	if _, err := os.Lstat(filepath.Join(ops.Roots()[0].Path, "link-to-passwd")); err == nil {
		wantTypes["link-to-passwd"] = "link"
		wantTypes["link-to-outside"] = "link"
	} else {
		t.Log("no symlink could be created here: the link rows of file_list run on Linux")
	}
	for name, wantType := range wantTypes {
		e, ok := byName[name]
		if !ok {
			t.Errorf("%s is missing from the listing", name)
			continue
		}
		if e.Type != wantType {
			t.Errorf("%s type = %q, want %q", name, e.Type, wantType)
		}
	}
	if _, err := ops.List(ctx, "xray", "secret.txt"); !errors.Is(err, ErrNotDir) {
		t.Errorf("List of a file = %v, want ErrNotDir", err)
	}
	linkOrSkip(t, filepath.Join(ops.Roots()[0].Path, "link-to-passwd"))
	if _, err := ops.List(ctx, "xray", "link-to-passwd"); !errors.Is(err, ErrSymlink) {
		t.Errorf("List of a symlink = %v, want ErrSymlink", err)
	}
}

// TestExcludedAgentFilesAreUnreachable covers ruling 9/13: agent.yml,
// desired.json and last_good.json are never reachable through a root, whatever
// the operation.
func TestExcludedAgentFilesAreUnreachable(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	state := filepath.Join(base, "state")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(state, 0o755); err != nil {
		t.Fatal(err)
	}
	agentYML := filepath.Join(root, "agent.yml")
	desired := filepath.Join(state, "desired.json")
	lastGood := filepath.Join(state, "last_good.json")
	for p, s := range map[string]string{agentYML: "Agent: {}", desired: "{}", lastGood: "{}"} {
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ops, err := New(Options{
		Roots:               []Root{{Name: "xray", Path: root}, {Name: "state", Path: state}},
		Excluded:            []string{agentYML, desired, lastGood},
		testAllowSystemRoot: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, tc := range []struct {
		root, rel string
	}{
		{"xray", "agent.yml"},
		{"state", "desired.json"},
		{"state", "last_good.json"},
	} {
		if _, err := ops.Resolve(tc.root, tc.rel); !errors.Is(err, ErrOutsideRoots) {
			t.Errorf("Resolve(%s, %s) = %v, want ErrOutsideRoots", tc.root, tc.rel, err)
		}
		if _, err := ops.Read(ctx, tc.root, tc.rel, 0, 0); !errors.Is(err, ErrOutsideRoots) {
			t.Errorf("Read(%s, %s) = %v, want ErrOutsideRoots", tc.root, tc.rel, err)
		}
		if _, err := ops.Write(ctx, tc.root, tc.rel, []byte("pwn"), 0o644, ""); !errors.Is(err, ErrOutsideRoots) {
			t.Errorf("Write(%s, %s) = %v, want ErrOutsideRoots", tc.root, tc.rel, err)
		}
		if err := ops.Delete(ctx, tc.root, tc.rel); !errors.Is(err, ErrOutsideRoots) {
			t.Errorf("Delete(%s, %s) = %v, want ErrOutsideRoots", tc.root, tc.rel, err)
		}
	}
	// The excluded names are hidden from a listing too.
	entries, err := ops.List(ctx, "xray", ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name == "agent.yml" {
			t.Error("file_list exposed agent.yml")
		}
	}
	entries, err = ops.List(ctx, "state", ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name == "desired.json" || e.Name == "last_good.json" {
			t.Errorf("file_list exposed %s", e.Name)
		}
	}
}

// TestNewRefusesUnsafeRoots covers the root validation: a system directory or a
// too-shallow path is refused at construction time.
func TestNewRefusesUnsafeRoots(t *testing.T) {
	cases := []struct {
		name string
		root string
	}{
		{"filesystem-root", string(filepath.Separator)},
		{"etc", "/etc"},
		// "/etc/xray" (a directory below /etc) is a valid root since 6b377f9:
		// /etc/W1nCray is the standard install; path_regress_test.go covers it.
		{"usr", "/usr"},
		{"var", "/var"},
		{"dev", "/dev"},
		{"proc", "/proc"},
		{"too-shallow", "/xray"},
		{"relative", "relative/path"},
		{"empty", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(Options{Roots: []Root{{Name: "xray", Path: tc.root}}}); err == nil {
				t.Fatalf("New accepted the root %q", tc.root)
			}
		})
	}
}

// TestNewRequiresNamedUniqueRoots covers the root bookkeeping.
func TestNewRequiresNamedUniqueRoots(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Options{Roots: []Root{{Path: root}}, testAllowSystemRoot: true}); err == nil {
		t.Error("New accepted a root without a name")
	}
	dup := []Root{{Name: "xray", Path: root}, {Name: "xray", Path: root}}
	if _, err := New(Options{Roots: dup, testAllowSystemRoot: true}); err == nil {
		t.Error("New accepted a duplicate root name")
	}
}

// TestUnrestrictedStillRefusesSymlinksAndSpecialFiles covers design section
// 3.9 rule 7: Files.Unrestricted only skips the roots lookup.
func TestUnrestrictedStillRefusesSymlinksAndSpecialFiles(t *testing.T) {
	base := t.TempDir()
	outside := filepath.Join(base, "outside")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(outside, "evil.txt")
	if err := os.WriteFile(target, []byte("evil"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	linkOK := trySymlink(target, link)
	if !linkOK {
		t.Log("no symlink can be created here: the Unrestricted symlink row runs on Linux")
	}
	ops, err := New(Options{Unrestricted: boolPtr(true), testAllowSystemRoot: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	// An absolute path outside any root is reachable...
	if _, err := ops.Read(ctx, "", target, 0, 0); err != nil {
		t.Errorf("Read of an absolute path with Unrestricted: %v", err)
	}
	// ...but a symlink is still refused...
	if linkOK {
		if _, err := ops.Read(ctx, "", link, 0, 0); !errors.Is(err, ErrSymlink) {
			t.Errorf("Read of a symlink with Unrestricted = %v, want ErrSymlink", err)
		}
	}
	// ...and the size limits still apply.
	if _, err := ops.Read(ctx, "", target, 0, DefaultMaxRead+1); !errors.Is(err, ErrTooLarge) {
		t.Errorf("Read over MaxRead with Unrestricted = %v, want ErrTooLarge", err)
	}
	if _, err := ops.Write(ctx, "", target, make([]byte, DefaultMaxWrite+1), 0o644, ""); !errors.Is(err, ErrTooLarge) {
		t.Errorf("Write over MaxWrite with Unrestricted = %v, want ErrTooLarge", err)
	}
	// A relative path is refused: Unrestricted means "absolute, anywhere", not
	// "relative, somewhere".
	if _, err := ops.Resolve("", "relative.txt"); !errors.Is(err, ErrBadPath) {
		t.Errorf("Resolve of a relative path with Unrestricted = %v, want ErrBadPath", err)
	}
	// The roots rules (excluding agent files) are gone, but the file must
	// still be a regular file.
	if err := ops.Delete(ctx, "", base); !errors.Is(err, ErrIsDir) {
		t.Errorf("Delete of a directory with Unrestricted = %v, want ErrIsDir", err)
	}
}

// TestRootsWithoutRoots covers the "no roots configured" case: the commands
// exist but can serve nothing.
func TestRootsWithoutRoots(t *testing.T) {
	ops, err := New(Options{testAllowSystemRoot: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := ops.RootNames(); len(got) != 0 {
		t.Errorf("RootNames = %v", got)
	}
	if _, err := ops.Resolve("xray", "a.txt"); !errors.Is(err, ErrNoRoots) {
		t.Errorf("Resolve without roots = %v, want ErrNoRoots", err)
	}
}

// TestUnrestrictedWithoutRoots is PLAN v10 requirement 2: an unrestricted
// machine needs no root at all. The panel names absolute paths with an empty
// root, and the filesystem root itself is listable.
func TestUnrestrictedWithoutRoots(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "note.txt")
	if err := os.WriteFile(file, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	ops, err := New(Options{Unrestricted: boolPtr(true), testAllowSystemRoot: true})
	if err != nil {
		t.Fatalf("New without roots must succeed when unrestricted: %v", err)
	}
	if !ops.Unrestricted() {
		t.Error("Unrestricted() = false")
	}
	if got := ops.RootNames(); len(got) != 0 {
		t.Errorf("RootNames = %v, want none", got)
	}
	ctx := context.Background()
	entries, err := ops.List(ctx, "", dir)
	if err != nil {
		t.Fatalf("List of an absolute directory without roots: %v", err)
	}
	if len(entries) != 1 || entries[0].Name != "note.txt" {
		t.Errorf("List = %+v", entries)
	}
	if got, err := ops.Resolve("", file); err != nil || got != file {
		t.Errorf("Resolve(%q) = %q, %v", file, got, err)
	}
	// The filesystem root is a directory listing like any other: the panel may
	// start browsing from the volume root ("/" on Unix, "C:\" on Windows).
	if _, err := ops.List(ctx, "", filepath.VolumeName(dir)+string(filepath.Separator)); err != nil {
		t.Errorf("List of the filesystem root: %v", err)
	}
	// The root argument is ignored, but the path still has to be absolute.
	if _, err := ops.Resolve("xray", "relative.txt"); !errors.Is(err, ErrBadPath) {
		t.Errorf("Resolve of a relative path = %v, want ErrBadPath", err)
	}
}

// TestAppendWholeFileDigest covers the chunked upload: append adds one chunk to
// an existing file, and every answer reports the size and the sha256 of the
// WHOLE file, so the panel can verify the assembled result.
func TestAppendWholeFileDigest(t *testing.T) {
	root, ops := testRoots(t)
	ctx := context.Background()
	chunks := [][]byte{[]byte("first chunk;"), []byte("second chunk;"), []byte("third chunk")}
	want := bytes.Join(chunks, nil)

	res, err := ops.Write(ctx, "xray", "big.bin", chunks[0], 0o644, "")
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if !res.Created || res.Size != int64(len(chunks[0])) || res.Append {
		t.Errorf("first write = %+v", res)
	}
	for i, chunk := range chunks[1:] {
		sum := sha256.Sum256(chunk)
		var err error
		res, err = ops.Append(ctx, "xray", "big.bin", chunk, hex.EncodeToString(sum[:]))
		if err != nil {
			t.Fatalf("Append #%d: %v", i+1, err)
		}
		if !res.Append {
			t.Errorf("Append #%d result does not report the append: %+v", i+1, res)
		}
		if res.Size != int64(len(bytes.Join(chunks[:i+2], nil))) {
			t.Errorf("Append #%d size = %d", i+1, res.Size)
		}
	}
	got, err := os.ReadFile(filepath.Join(root, "big.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("file = %q, want %q", got, want)
	}
	wantSum := sha256.Sum256(want)
	if res.SHA256 != hex.EncodeToString(wantSum[:]) {
		t.Errorf("whole-file sha256 = %s, want %s", res.SHA256, hex.EncodeToString(wantSum[:]))
	}
	if res.Size != int64(len(want)) {
		t.Errorf("whole-file size = %d, want %d", res.Size, len(want))
	}
	// The payload is still checked against the caller's sha256.
	if _, err := ops.Append(ctx, "xray", "big.bin", []byte("x"), strings.Repeat("0", 64)); !errors.Is(err, ErrHashMismatch) {
		t.Errorf("Append with a bad sha256 = %v, want ErrHashMismatch", err)
	}
	// The size limit applies to one chunk, not to the file.
	if _, err := ops.Append(ctx, "xray", "big.bin", make([]byte, DefaultMaxWrite+1), ""); !errors.Is(err, ErrTooLarge) {
		t.Errorf("Append over MaxWrite = %v, want ErrTooLarge", err)
	}
}

// TestAppendRefusesMissingAndSpecialFiles: an append never creates the file (a
// lost chunk must fail loudly) and never follows a symlink.
func TestAppendRefusesMissingAndSpecialFiles(t *testing.T) {
	root, ops := testRoots(t)
	ctx := context.Background()
	if _, err := ops.Append(ctx, "xray", "not-there.bin", []byte("x"), ""); !errors.Is(err, ErrNotExist) {
		t.Errorf("Append to a missing file = %v, want ErrNotExist", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "not-there.bin")); !errors.Is(err, os.ErrNotExist) {
		t.Error("Append created the missing file")
	}
	if _, err := ops.Append(ctx, "xray", "sub", []byte("x"), ""); !errors.Is(err, ErrIsDir) {
		t.Errorf("Append to a directory = %v, want ErrIsDir", err)
	}
	if _, err := ops.Append(ctx, "xray", "../outside/evil.txt", []byte("x"), ""); !errors.Is(err, ErrBadPath) {
		t.Errorf("Append outside the root = %v, want ErrBadPath", err)
	}
	if link, err := os.Lstat(filepath.Join(root, "link-to-outside")); err == nil && link != nil {
		if _, err := ops.Append(ctx, "xray", "link-to-outside", []byte("x"), ""); !errors.Is(err, ErrSymlink) {
			t.Errorf("Append through a symlink = %v, want ErrSymlink", err)
		}
	}
}

// TestMkdirCreatesParents covers file_mkdir: mkdir -p semantics, the default
// mode 0755 and the directory mode whitelist.
func TestMkdirCreatesParents(t *testing.T) {
	root, ops := testRoots(t)
	ctx := context.Background()

	res, err := ops.Mkdir(ctx, "xray", "a/b/c", 0)
	if err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if !res.Created {
		t.Error("Mkdir of a new path reports Created = false")
	}
	if res.Path != filepath.Join(root, "a", "b", "c") {
		t.Errorf("Mkdir path = %q", res.Path)
	}
	for _, rel := range []string{"a", "a/b", "a/b/c"} {
		fi, err := os.Lstat(filepath.Join(root, rel))
		if err != nil || !fi.IsDir() {
			t.Fatalf("%s: %v", rel, err)
		}
	}
	if fi, _ := os.Lstat(filepath.Join(root, "a", "b", "c")); !runtimeIsWindows && fi.Mode().Perm() != 0o755 {
		t.Errorf("default directory mode = %04o, want 0755", fi.Mode().Perm())
	}
	// A second call is a no-op, not an error (mkdir -p).
	again, err := ops.Mkdir(ctx, "xray", "a/b/c", 0)
	if err != nil || again.Created {
		t.Errorf("second Mkdir = %+v, %v", again, err)
	}
	// An explicit mode is honoured (the executable bit needs no AllowExec on a
	// directory: it is what makes it searchable).
	res, err = ops.Mkdir(ctx, "xray", "private", 0o700)
	if err != nil {
		t.Fatalf("Mkdir 0700: %v", err)
	}
	if fi, _ := os.Lstat(res.Path); !runtimeIsWindows && fi.Mode().Perm() != 0o700 {
		t.Errorf("mode = %04o, want 0700", fi.Mode().Perm())
	}
	// A world-writable directory is refused, and so is a special bit.
	if _, err := ops.Mkdir(ctx, "xray", "open", 0o777); !errors.Is(err, ErrBadPath) {
		t.Errorf("Mkdir 0777 = %v, want ErrBadPath", err)
	}
	if _, err := ops.Mkdir(ctx, "xray", "sticky", 0o1777); !errors.Is(err, ErrSpecialMode) {
		t.Errorf("Mkdir 1777 = %v, want ErrSpecialMode", err)
	}
	// An existing regular file is not a directory.
	if _, err := ops.Mkdir(ctx, "xray", "secret.txt", 0); !errors.Is(err, ErrNotDir) {
		t.Errorf("Mkdir over a file = %v, want ErrNotDir", err)
	}
}

// TestMkdirRefusesEscapes: the new command obeys exactly the same path rules.
func TestMkdirRefusesEscapes(t *testing.T) {
	_, ops := testRoots(t)
	ctx := context.Background()
	for _, tc := range []struct {
		root, path string
		want       error
	}{
		{"xray", "../outside/evil", ErrBadPath},
		{"xray", "/etc/w1n", ErrBadPath},
		{"nope", "a", ErrUnknownRoot},
		{"state", "desired.json", ErrOutsideRoots},
	} {
		if _, err := ops.Mkdir(ctx, tc.root, tc.path, 0); !errors.Is(err, tc.want) {
			t.Errorf("Mkdir(%s, %s) = %v, want %v", tc.root, tc.path, err, tc.want)
		}
	}
}

// TestRenameMovesAndNeverOverwrites covers file_rename: a move inside the root
// works, an existing target is refused, and a missing source is reported.
func TestRenameMovesAndNeverOverwrites(t *testing.T) {
	root, ops := testRoots(t)
	ctx := context.Background()

	res, err := ops.Rename(ctx, "xray", "secret.txt", "sub/moved.txt")
	if err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if !res.Renamed || res.To != filepath.Join(root, "sub", "moved.txt") {
		t.Errorf("Rename = %+v", res)
	}
	if _, err := os.Lstat(filepath.Join(root, "secret.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Error("the source still exists after Rename")
	}
	if b, err := os.ReadFile(res.To); err != nil || string(b) != "top secret" {
		t.Errorf("moved content = %q, %v", b, err)
	}
	// The target must not exist: an existing file (or directory) is refused
	// and left untouched.
	if _, err := ops.Rename(ctx, "xray", "sub/moved.txt", "sub/inside.txt"); !errors.Is(err, ErrExists) {
		t.Errorf("Rename over an existing file = %v, want ErrExists", err)
	}
	if b, err := os.ReadFile(filepath.Join(root, "sub", "inside.txt")); err != nil || string(b) != "inside" {
		t.Errorf("the target was modified: %q, %v", b, err)
	}
	if _, err := ops.Rename(ctx, "xray", "sub/moved.txt", "sub"); !errors.Is(err, ErrExists) {
		t.Errorf("Rename over a directory = %v, want ErrExists", err)
	}
	if _, err := ops.Rename(ctx, "xray", "gone.txt", "other.txt"); !errors.Is(err, ErrNotExist) {
		t.Errorf("Rename of a missing source = %v, want ErrNotExist", err)
	}
	if _, err := ops.Rename(ctx, "xray", "sub/moved.txt", "sub/moved.txt"); !errors.Is(err, ErrBadPath) {
		t.Errorf("Rename onto itself = %v, want ErrBadPath", err)
	}
	// A missing target directory is refused instead of being created.
	if _, err := ops.Rename(ctx, "xray", "sub/moved.txt", "nodir/x.txt"); !errors.Is(err, ErrBadPath) {
		t.Errorf("Rename into a missing directory = %v, want ErrBadPath", err)
	}
}

// TestRenameRefusesEscapes: both ends go through Resolve, so a rename can never
// move a file out of its root.
func TestRenameRefusesEscapes(t *testing.T) {
	_, ops := testRoots(t)
	ctx := context.Background()
	for _, tc := range []struct {
		name, root, from, to string
		want                 error
	}{
		{"source escapes", "xray", "../outside/evil.txt", "moved.txt", ErrBadPath},
		{"target escapes", "xray", "secret.txt", "../outside/evil.txt", ErrBadPath},
		{"target absolute", "xray", "secret.txt", "/etc/moved.txt", ErrBadPath},
		{"excluded source", "state", "desired.json", "moved.json", ErrOutsideRoots},
		{"excluded target", "state", "sub", "desired.json", ErrOutsideRoots},
		{"unknown root", "nope", "a", "b", ErrUnknownRoot},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ops.Rename(ctx, tc.root, tc.from, tc.to); !errors.Is(err, tc.want) {
				t.Errorf("Rename = %v, want %v", err, tc.want)
			}
		})
	}
	// A symlink is never moved (it would carry its target's meaning elsewhere).
	if _, err := os.Lstat(filepath.Join(ops.Roots()[0].Path, "link-to-outside")); err == nil {
		if _, err := ops.Rename(ctx, "xray", "link-to-outside", "sub/link"); !errors.Is(err, ErrSymlink) {
			t.Errorf("Rename of a symlink = %v, want ErrSymlink", err)
		}
	}
}

// TestUnrestrictedMkdirAndRename: the new commands use absolute paths when the
// machine is unrestricted, exactly like the old ones.
func TestUnrestrictedMkdirAndRename(t *testing.T) {
	base := t.TempDir()
	ops, err := New(Options{Unrestricted: boolPtr(true), testAllowSystemRoot: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	dir := filepath.Join(base, "deep", "er")
	if _, err := ops.Mkdir(ctx, "", dir, 0o755); err != nil {
		t.Fatalf("Mkdir %s: %v", dir, err)
	}
	file := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(base, "b.txt")
	if res, err := ops.Rename(ctx, "", file, moved); err != nil || !res.Renamed {
		t.Fatalf("Rename = %+v, %v", res, err)
	}
	if _, err := ops.Rename(ctx, "", moved, "relative.txt"); !errors.Is(err, ErrBadPath) {
		t.Errorf("Rename to a relative path = %v, want ErrBadPath", err)
	}
	if _, err := ops.Mkdir(ctx, "", "relative", 0); !errors.Is(err, ErrBadPath) {
		t.Errorf("Mkdir of a relative path = %v, want ErrBadPath", err)
	}
}

// TestFileListReportsModeAndMTime pins the file_list row shape: the panel needs
// the permission bits and the modification time of every entry.
func TestFileListReportsModeAndMTime(t *testing.T) {
	root, ops := testRoots(t)
	entries, err := ops.List(context.Background(), "xray", ".")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if e.Name != "secret.txt" {
			continue
		}
		found = true
		if !runtimeIsWindows && e.Mode != "0644" {
			t.Errorf("mode = %q, want 0644", e.Mode)
		}
		if e.Mode == "" {
			t.Error("the entry has no mode")
		}
		fi, err := os.Lstat(filepath.Join(root, "secret.txt"))
		if err != nil {
			t.Fatal(err)
		}
		if e.MTime != fi.ModTime().Unix() {
			t.Errorf("mtime = %d, want %d", e.MTime, fi.ModTime().Unix())
		}
	}
	if !found {
		t.Errorf("secret.txt is not in the listing: %+v", entries)
	}
}

func boolPtr(v bool) *bool { return &v }

var _ driver.Logger = nopLog{}

// TestUnrestrictedKeepsNamedRoots: an unrestricted machine still resolves a
// named root plus a relative path (the panel's Xray config view reads
// {root:"xray", path:"route.json"}); only the empty root takes an absolute path.
func TestUnrestrictedKeepsNamedRoots(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "route.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	ops, err := New(Options{Unrestricted: boolPtr(true), Roots: []Root{{Name: "xray", Path: dir}}, testAllowSystemRoot: true})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ops.Resolve("xray", "route.json"); err != nil || got != filepath.Join(dir, "route.json") {
		t.Fatalf("Resolve(xray, route.json) = %q, %v", got, err)
	}
	if _, err := ops.Resolve("xray", "../escape"); !errors.Is(err, ErrBadPath) {
		t.Errorf("a named root must still refuse ..: %v", err)
	}
	abs := filepath.Join(dir, "route.json")
	if got, err := ops.Resolve("", abs); err != nil || got != abs {
		t.Errorf("Resolve(\"\", abs) = %q, %v", got, err)
	}
}
