package install

import (
	"archive/tar"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/W1nCwC/W1nCray/kernel"
	"github.com/W1nCwC/W1nCray/kernel/manifest"
)

// The multi-member coverage of the direct path (frp: frpc + frps in one
// tar.gz), the cases appended next to direct_test.go: it uses the same
// fixture and helpers, and no existing case or assertion is touched.

// readMarkerFile reads the .installed.json of an installed version.
func readMarkerFile(t *testing.T, in *Installer, name, version string) marker {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(in.verDir(name, version), ".installed.json"))
	if err != nil {
		t.Fatalf("reading the installed marker: %v", err)
	}
	var mk marker
	if err := json.Unmarshal(b, &mk); err != nil {
		t.Fatalf("marker %s: %v", b, err)
	}
	return mk
}

// frpMembers is the frp member list: the two binaries of one archive.
func frpMembers() []DirectMember {
	return []DirectMember{{From: "frp_0.71.0_linux_amd64/frpc", To: "frpc"}, {From: "frp_0.71.0_linux_amd64/frps", To: "frps"}}
}

// TestInstallDirectMembersInstallsBothBinaries: one tar.gz installs frpc and
// frps in one commit, and an unlisted member of the same archive stays out.
func TestInstallDirectMembersInstallsBothBinaries(t *testing.T) {
	f := newDirectFixture(t, true)
	frpc := fakeBin("0.71.0", 512)
	frps := fakeBin("0.71.0", 700)
	archive := mkTarGz(t,
		tarEntry{Name: "frp_0.71.0_linux_amd64/frpc", Data: frpc},
		tarEntry{Name: "frp_0.71.0_linux_amd64/frps", Data: frps},
		tarEntry{Name: "frp_0.71.0_linux_amd64/LICENSE", Data: []byte("Apache-2.0")},
	)
	fs := newFileServer(t)
	url := fs.put("/frp_0.71.0_linux_amd64.tar.gz", archive)

	inst, err := f.in.InstallDirect(context.Background(), DirectInstall{
		Name: "frp", Version: "0.71.0", URL: url,
		SHA256: sum(archive), Archive: manifest.ArchiveTarGz,
		Members: frpMembers(),
	})
	if err != nil {
		t.Fatalf("InstallDirect: %v", err)
	}
	if inst.Version != "0.71.0" {
		t.Errorf("version = %q", inst.Version)
	}
	dir := filepath.Dir(inst.Path)
	if filepath.Base(inst.Path) != "frpc" {
		t.Errorf("installed path = %q, want the frp run binary frpc", inst.Path)
	}
	for _, name := range []string{"frpc", "frps"} {
		p := filepath.Join(dir, name)
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if string(b) != string(map[string][]byte{"frpc": frpc, "frps": frps}[name]) {
			t.Errorf("%s differs from the archive member", name)
		}
		if runtime.GOOS != "windows" {
			fi, err := os.Stat(p)
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode().Perm()&0o111 == 0 {
				t.Errorf("%s mode = %v, want an executable bit", name, fi.Mode())
			}
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "LICENSE")); err == nil {
		t.Error("an unlisted member must not be extracted")
	}

	entries, err := f.in.List()
	if err != nil {
		t.Fatal(err)
	}
	var current bool
	for _, e := range entries {
		if e.Name == "frp" && e.Version == "0.71.0" && e.Current {
			current = true
		}
	}
	if !current {
		t.Errorf("frp@0.71.0 is not the current entry: %+v", entries)
	}

	mk := readMarkerFile(t, f.in, "frp", "0.71.0")
	if len(mk.Files) != 2 {
		t.Fatalf("marker files = %+v, want frpc and frps", mk.Files)
	}
	want := map[string]int64{"frpc": int64(len(frpc)), "frps": int64(len(frps))}
	for _, mf := range mk.Files {
		if want[mf.To] != mf.Size {
			t.Errorf("marker file %+v, want size %d", mf, want[mf.To])
		}
		if mf.Mode != "0755" {
			t.Errorf("marker file %+v, want mode 0755", mf)
		}
	}
	if mk.Binary != "frpc" {
		t.Errorf("marker binary = %q, want frpc", mk.Binary)
	}
}

// TestInstallDirectMembersRefusesMissingMember: a listed member the archive
// does not carry refuses the whole install.
func TestInstallDirectMembersRefusesMissingMember(t *testing.T) {
	f := newDirectFixture(t, true)
	archive := mkTarGz(t, tarEntry{Name: "frp_0.71.0_linux_amd64/frpc", Data: fakeBin("0.71.0", 256)})
	fs := newFileServer(t)
	url := fs.put("/frp.tar.gz", archive)

	_, err := f.in.InstallDirect(context.Background(), DirectInstall{
		Name: "frp", Version: "0.71.0", URL: url,
		SHA256: sum(archive), Archive: manifest.ArchiveTarGz,
		Members: frpMembers(),
	})
	if err == nil || kernel.Code(err) != "verify_failed" {
		t.Fatalf("err = %v, want code verify_failed", err)
	}
	if l, _ := f.in.List(); len(l) != 0 {
		t.Errorf("a refused install must not touch the kernel directory: %+v", l)
	}
}

// TestInstallDirectMembersRefusesRunBinaryNotAMember: the self-checked binary
// must be one of the installed files, and the refusal happens before the
// download.
func TestInstallDirectMembersRefusesRunBinaryNotAMember(t *testing.T) {
	f := newDirectFixture(t, true)
	archive := mkTarGz(t, tarEntry{Name: "frps", Data: fakeBin("0.71.0", 256)})
	fs := newFileServer(t)
	url := fs.put("/frp.tar.gz", archive)

	// frp's default run binary is frpc, which this list does not install.
	_, err := f.in.InstallDirect(context.Background(), DirectInstall{
		Name: "frp", Version: "0.71.0", URL: url,
		SHA256: sum(archive), Archive: manifest.ArchiveTarGz,
		Members: []DirectMember{{From: "frps", To: "frps"}},
	})
	if err == nil || kernel.Code(err) != "verify_failed" {
		t.Fatalf("err = %v, want code verify_failed", err)
	}
	if n := fs.hitCount("/frp.tar.gz"); n != 0 {
		t.Errorf("the archive was downloaded %d times, want 0 (the list is refused first)", n)
	}
	if l, _ := f.in.List(); len(l) != 0 {
		t.Errorf("a refused install must not touch the kernel directory: %+v", l)
	}
}

// TestInstallDirectMembersRefusesDuplicates: a repeated To or a repeated
// archive member is ambiguous and refused.
func TestInstallDirectMembersRefusesDuplicates(t *testing.T) {
	f := newDirectFixture(t, true)
	archive := mkTarGz(t, tarEntry{Name: "frpc", Data: fakeBin("0.71.0", 64)})
	fs := newFileServer(t)
	url := fs.put("/frp.tar.gz", archive)

	cases := map[string][]DirectMember{
		"same installed name": {{From: "frpc", To: "frpc"}, {From: "frps", To: "frpc"}},
		"same archive member": {{From: "frpc", To: "frpc"}, {From: "frpc", To: "frps"}},
	}
	for label, members := range cases {
		t.Run(label, func(t *testing.T) {
			_, err := f.in.InstallDirect(context.Background(), DirectInstall{
				Name: "frp", Version: "0.71.0", URL: url,
				SHA256: sum(archive), Archive: manifest.ArchiveTarGz, Members: members,
			})
			if err == nil || kernel.Code(err) != "verify_failed" {
				t.Fatalf("err = %v, want code verify_failed", err)
			}
			if n := fs.hitCount("/frp.tar.gz"); n != 0 {
				t.Errorf("the archive was downloaded %d times, want 0", n)
			}
		})
	}
}

// TestInstallDirectMembersRefusesUnsafePaths: member names and archive entries
// may not escape the version directory.
func TestInstallDirectMembersRefusesUnsafePaths(t *testing.T) {
	f := newDirectFixture(t, true)
	good := mkTarGz(t, tarEntry{Name: "frpc", Data: fakeBin("0.71.0", 64)})
	evil := mkTarGz(t, tarEntry{Name: "frpc", Data: fakeBin("0.71.0", 64)}, tarEntry{Name: "../evil", Data: []byte("x")})
	fs := newFileServer(t)
	goodURL := fs.put("/good.tar.gz", good)
	evilURL := fs.put("/evil.tar.gz", evil)

	lists := map[string][]DirectMember{
		"from with a parent":    {{From: "../frpc", To: "frpc"}},
		"absolute from":         {{From: "/frpc", To: "frpc"}},
		"to with a directory":   {{From: "frpc", To: "sub/frpc"}},
		"to with a parent":      {{From: "frpc", To: "../frpc"}},
		"to is the marker file": {{From: "frpc", To: ".installed.json"}},
		"from with a backslash": {{From: `a\frpc`, To: "frpc"}},
		"empty to":              {{From: "frpc", To: ""}},
	}
	for label, members := range lists {
		t.Run(label, func(t *testing.T) {
			_, err := f.in.InstallDirect(context.Background(), DirectInstall{
				Name: "frp", Version: "0.71.0", URL: goodURL,
				SHA256: sum(good), Archive: manifest.ArchiveTarGz, Members: members,
			})
			if err == nil || kernel.Code(err) != "verify_failed" {
				t.Fatalf("err = %v, want code verify_failed", err)
			}
			if n := fs.hitCount("/good.tar.gz"); n != 0 {
				t.Errorf("the archive was downloaded %d times, want 0", n)
			}
		})
	}

	t.Run("unsafe entry in the archive", func(t *testing.T) {
		_, err := f.in.InstallDirect(context.Background(), DirectInstall{
			Name: "frp", Version: "0.71.0", URL: evilURL,
			SHA256: sum(evil), Archive: manifest.ArchiveTarGz, Members: frpMembers(),
		})
		if err == nil || kernel.Code(err) != "verify_failed" {
			t.Fatalf("err = %v, want code verify_failed", err)
		}
	})
}

// TestInstallDirectMembersRefusesWrongHashAndSize: the archive hash and size
// anchor the multi-file path exactly like the single-file one.
func TestInstallDirectMembersRefusesWrongHashAndSize(t *testing.T) {
	f := newDirectFixture(t, true)
	archive := mkTarGz(t,
		tarEntry{Name: "frpc", Data: fakeBin("0.71.0", 256)},
		tarEntry{Name: "frps", Data: fakeBin("0.71.0", 256)},
	)
	fs := newFileServer(t)
	url := fs.put("/frp.tar.gz", archive)

	cases := []struct {
		name string
		sha  string
		size int64
	}{
		{"wrong sha256", "abababababababababababababababababababababababababababababababab", int64(len(archive))},
		{"wrong size", sum(archive), int64(len(archive)) + 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := f.in.InstallDirect(context.Background(), DirectInstall{
				Name: "frp", Version: "0.71.0", URL: url,
				SHA256: tc.sha, Size: tc.size, Archive: manifest.ArchiveTarGz, Members: frpMembers(),
			})
			if err == nil || kernel.Code(err) != "verify_failed" {
				t.Fatalf("err = %v, want code verify_failed", err)
			}
			if l, _ := f.in.List(); len(l) != 0 {
				t.Errorf("a refused install must not touch the kernel directory: %+v", l)
			}
		})
	}
}

// TestInstallDirectMembersRefusesFormatAndArity: members require an explicit
// tar.gz, cannot be combined with from/to, and are bounded.
func TestInstallDirectMembersRefusesFormatAndArity(t *testing.T) {
	f := newDirectFixture(t, true)
	archive := mkTarGz(t, tarEntry{Name: "frpc", Data: fakeBin("0.71.0", 64)})
	fs := newFileServer(t)
	url := fs.put("/frp.tar.gz", archive)

	tooMany := make([]DirectMember, 0, 9)
	for i := 0; i < 9; i++ {
		to := "m" + string(rune('a'+i))
		tooMany = append(tooMany, DirectMember{From: to, To: to})
	}

	cases := []struct {
		name string
		di   DirectInstall
	}{
		{"empty archive with members", DirectInstall{
			Name: "frp", Version: "0.71.0", URL: url, SHA256: sum(archive), Members: frpMembers()}},
		{"gz with members", DirectInstall{
			Name: "frp", Version: "0.71.0", URL: url, SHA256: sum(archive),
			Archive: manifest.ArchiveGz, Members: frpMembers()}},
		{"members with from/to", DirectInstall{
			Name: "frp", Version: "0.71.0", URL: url, SHA256: sum(archive),
			Archive: manifest.ArchiveTarGz, From: "frpc", To: "frpc", Members: frpMembers()}},
		{"nine members", DirectInstall{
			Name: "frp", Version: "0.71.0", URL: url, SHA256: sum(archive),
			Archive: manifest.ArchiveTarGz, Members: tooMany}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := f.in.InstallDirect(context.Background(), tc.di)
			if err == nil || kernel.Code(err) != "verify_failed" {
				t.Fatalf("err = %v, want code verify_failed", err)
			}
			if n := fs.hitCount("/frp.tar.gz"); n != 0 {
				t.Errorf("the archive was downloaded %d times, want 0", n)
			}
		})
	}
}

// TestInstallDirectMembersRefusesSymlink: a wanted member that is a symbolic
// link is not a regular file.
func TestInstallDirectMembersRefusesSymlink(t *testing.T) {
	f := newDirectFixture(t, true)
	archive := mkTarGz(t,
		tarEntry{Name: "frpc", Type: tar.TypeSymlink, Link: "frps"},
		tarEntry{Name: "frps", Data: fakeBin("0.71.0", 128)},
	)
	fs := newFileServer(t)
	url := fs.put("/frp.tar.gz", archive)

	_, err := f.in.InstallDirect(context.Background(), DirectInstall{
		Name: "frp", Version: "0.71.0", URL: url,
		SHA256: sum(archive), Archive: manifest.ArchiveTarGz, Members: frpMembers(),
	})
	if err == nil || kernel.Code(err) != "verify_failed" {
		t.Fatalf("err = %v, want code verify_failed", err)
	}
	if l, _ := f.in.List(); len(l) != 0 {
		t.Errorf("a refused install must not touch the kernel directory: %+v", l)
	}
}
