package install

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/driver/frp"
	"github.com/W1nCwC/W1nCray/kernel"
	"github.com/W1nCwC/W1nCray/kernel/manifest"
	"github.com/W1nCwC/W1nCray/kernel/platform"
)

// ownTable replaces the generated built-in release table for one test and
// restores it afterwards. The tests must not run in parallel: the table is a
// package-level variable.
func ownTable(t *testing.T, rows ...ownKernel) {
	t.Helper()
	old := ownKernelTable
	ownKernelTable = rows
	t.Cleanup(func() { ownKernelTable = old })
}

// ownInstaller builds an Installer with the built-in table enabled for plat.
func ownInstaller(t *testing.T, f *fixture, dir string, plat platform.Info, mod ...func(*Config)) *Installer {
	t.Helper()
	mods := append([]func(*Config){func(c *Config) {
		c.OwnKernels = true
		c.Platform = &plat
	}}, mod...)
	return f.installer(dir, mods...)
}

// ownGzRow serves one gzip build from fs and returns the table row for it.
func ownGzRow(t *testing.T, fs *fileServer, name, version, platKey, variant, path, binVersion string, pad int) ownKernel {
	t.Helper()
	data := mkGz(t, fakeBin(binVersion, pad))
	return ownKernel{
		Name: name, Version: version, Platform: platKey, Variant: variant,
		URL: fs.put(path, data), SHA256: sum(data), Size: int64(len(data)),
		Archive: manifest.ArchiveGz,
	}
}

// ownFrpRow serves one frp tar.gz (frpc and frps) and returns its table row.
func ownFrpRow(t *testing.T, fs *fileServer, version, platKey, path string, pad int) ownKernel {
	t.Helper()
	data := mkTarGz(t,
		tarEntry{Name: "frpc", Data: fakeBin(version, pad)},
		tarEntry{Name: "frps", Data: fakeBin(version, pad+64)},
	)
	return ownKernel{
		Name: "frp", Version: version, Platform: platKey,
		URL: fs.put(path, data), SHA256: sum(data), Size: int64(len(data)),
		Archive: manifest.ArchiveTarGz, Members: ownFrpMembers,
	}
}

// TestOwnKernelsHitNeverReadsManifest proves the short circuit: a pin the table
// holds is installed from the release asset even when the manifest is missing,
// points somewhere else, or has expired.
func TestOwnKernelsHitNeverReadsManifest(t *testing.T) {
	t.Run("no-manifest-at-all", func(t *testing.T) {
		f := newFixture(t)
		own := newFileServer(t)
		ownTable(t, ownGzRow(t, own, "gost", "3.3.0", "linux/amd64", "", "/gost.gz", "3.3.0", 64))
		in := ownInstaller(t, f, t.TempDir(), f.plat)

		inst, err := in.Ensure(context.Background(), pin("gost", "3.3.0"))
		if err != nil {
			t.Fatalf("Ensure without a manifest: %v", err)
		}
		if inst.Version != "3.3.0" {
			t.Fatalf("installed version = %q, want 3.3.0", inst.Version)
		}
		got, err := os.ReadFile(inst.Path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, fakeBin("3.3.0", 64)) {
			t.Fatal("the installed bytes are not the built-in table's asset")
		}
		if n := own.hitCount("/gost.gz"); n != 1 {
			t.Fatalf("table asset hits = %d, want 1", n)
		}
	})

	t.Run("loaded-manifest-points-elsewhere", func(t *testing.T) {
		f := newFixture(t)
		man := newFileServer(t)
		own := newFileServer(t)
		ownTable(t, ownGzRow(t, own, "gost", "3.3.0", "linux/amd64", "", "/gost.gz", "3.3.0", 64))
		// The manifest lists the same version from another server, with a
		// different payload: it must not be touched at all.
		k := publish(t, f, man, kern{Name: "gost", Version: "3.3.0",
			Members: map[string][]byte{"gost": fakeBin("3.3.0", 4096)},
			Extract: map[string]string{"gost": "gost"}})
		in := ownInstaller(t, f, t.TempDir(), f.plat)
		if err := in.LoadManifest(f.sign(k)); err != nil {
			t.Fatal(err)
		}

		inst, err := in.Ensure(context.Background(), pin("gost", "3.3.0"))
		if err != nil {
			t.Fatalf("Ensure with a manifest loaded: %v", err)
		}
		got, err := os.ReadFile(inst.Path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, fakeBin("3.3.0", 64)) {
			t.Fatal("the manifest's payload was installed instead of the table's")
		}
		if n := man.hitCount("/gost-3.3.0.bin"); n != 0 {
			t.Fatalf("the manifest server was contacted %d time(s)", n)
		}
	})

	t.Run("expired-manifest", func(t *testing.T) {
		f := newFixture(t)
		man := newFileServer(t)
		own := newFileServer(t)
		ownTable(t, ownGzRow(t, own, "gost", "3.3.0", "linux/amd64", "", "/gost.gz", "3.3.0", 64))
		k := publish(t, f, man, kern{Name: "gost", Version: "3.3.0",
			Members: map[string][]byte{"gost": fakeBin("3.3.0", 4096)},
			Extract: map[string]string{"gost": "gost"}})
		in := ownInstaller(t, f, t.TempDir(), f.plat)
		if err := in.LoadManifest(f.sign(k)); err != nil {
			t.Fatal(err)
		}
		f.clk.Add(31 * 24 * time.Hour) // the manifest is stale now

		if _, err := in.Ensure(context.Background(), pin("gost", "3.3.0")); err != nil {
			t.Fatalf("Ensure with an expired manifest: %v", err)
		}
		if n := man.hitCount("/gost-3.3.0.bin"); n != 0 {
			t.Fatalf("the manifest server was contacted %d time(s)", n)
		}
	})
}

// TestOwnKernelsMissIsRefused proves a table miss never falls back to the
// manifest: no download, nothing installed and no back-off recorded.
func TestOwnKernelsMissIsRefused(t *testing.T) {
	t.Run("version-not-in-the-table", func(t *testing.T) {
		f := newFixture(t)
		man := newFileServer(t)
		own := newFileServer(t)
		ownTable(t, ownGzRow(t, own, "gost", "3.3.0", "linux/amd64", "", "/gost.gz", "3.3.0", 64))
		// The manifest does list 9.9.9: it must still be refused.
		k := publish(t, f, man, kern{Name: "gost", Version: "9.9.9",
			Members: map[string][]byte{"gost": fakeBin("9.9.9", 4096)},
			Extract: map[string]string{"gost": "gost"}})
		in := ownInstaller(t, f, t.TempDir(), f.plat)
		if err := in.LoadManifest(f.sign(k)); err != nil {
			t.Fatal(err)
		}

		_, err := in.Ensure(context.Background(), pin("gost", "9.9.9"))
		if !errors.Is(err, kernel.ErrUnknownKernel) {
			t.Fatalf("Ensure(gost@9.9.9) = %v, want ErrUnknownKernel", err)
		}
		if n := man.hitCount("/gost-9.9.9.bin"); n != 0 {
			t.Fatalf("the manifest server was contacted %d time(s)", n)
		}
		if list, err := in.List(); err != nil || len(list) != 0 {
			t.Fatalf("List() = %+v (err %v), want nothing installed", list, err)
		}
		if len(in.st.Bad) != 0 {
			t.Fatalf("a table miss recorded a back-off: %+v", in.st.Bad)
		}
	})

	t.Run("platform-without-the-kernel", func(t *testing.T) {
		f := newFixture(t)
		own := newFileServer(t)
		ownTable(t, ownGzRow(t, own, "realm", "2.9.6", "linux/amd64", "musl-full", "/realm.gz", "2.9.6", 64))
		plat := platform.Info{GOOS: "linux", GOARCH: "riscv64", Libc: "musl"}
		in := ownInstaller(t, f, t.TempDir(), plat)

		_, err := in.Ensure(context.Background(), pin("realm", "2.9.6"))
		if !errors.Is(err, kernel.ErrUnknownKernel) {
			t.Fatalf("Ensure(realm@2.9.6 on riscv64) = %v, want ErrUnknownKernel", err)
		}
		if n := own.hitCount("/realm.gz"); n != 0 {
			t.Fatalf("the table asset was contacted %d time(s)", n)
		}
	})
}

// TestOwnKernelsEmptyVersionPicksLatest covers the empty pin: semantic order,
// variant compatibility and the "nothing for this platform" refusal.
func TestOwnKernelsEmptyVersionPicksLatest(t *testing.T) {
	t.Run("semantic-order", func(t *testing.T) {
		f := newFixture(t)
		own := newFileServer(t)
		ownTable(t,
			ownGzRow(t, own, "gost", "3.2.1", "linux/amd64", "", "/g321.gz", "3.2.1", 16),
			ownGzRow(t, own, "gost", "3.3.0", "linux/amd64", "", "/g330.gz", "3.3.0", 16),
			ownGzRow(t, own, "gost", "3.10.0", "linux/amd64", "", "/g3100.gz", "3.10.0", 16),
		)
		in := ownInstaller(t, f, t.TempDir(), f.plat)

		inst, err := in.Ensure(context.Background(), pin("gost", ""))
		if err != nil {
			t.Fatalf("Ensure(gost@\"\"): %v", err)
		}
		if inst.Version != "3.10.0" {
			t.Fatalf("default version = %q, want the semantic latest 3.10.0", inst.Version)
		}
	})

	t.Run("incompatible-higher-version-is-skipped", func(t *testing.T) {
		f := newFixture(t)
		own := newFileServer(t)
		plat := platform.Info{GOOS: "linux", GOARCH: "amd64", Float: "softfloat", Libc: "musl"}
		ownTable(t,
			ownGzRow(t, own, "gost", "3.3.0", "linux/amd64", "", "/g330.gz", "3.3.0", 16),
			ownGzRow(t, own, "gost", "3.11.0", "linux/amd64", "hardfloat", "/g3110.gz", "3.11.0", 16),
		)
		in := ownInstaller(t, f, t.TempDir(), plat)

		inst, err := in.Ensure(context.Background(), pin("gost", ""))
		if err != nil {
			t.Fatalf("Ensure(gost@\"\"): %v", err)
		}
		if inst.Version != "3.3.0" {
			t.Fatalf("default version = %q, want 3.3.0 (the hardfloat row cannot run here)", inst.Version)
		}
		if n := own.hitCount("/g3110.gz"); n != 0 {
			t.Fatalf("the incompatible row was downloaded %d time(s)", n)
		}
	})

	t.Run("nothing-for-this-platform", func(t *testing.T) {
		f := newFixture(t)
		own := newFileServer(t)
		ownTable(t, ownGzRow(t, own, "gost", "3.3.0", "linux/arm64", "", "/gost.gz", "3.3.0", 16))
		in := ownInstaller(t, f, t.TempDir(), f.plat)

		_, err := in.Ensure(context.Background(), pin("gost", ""))
		if !errors.Is(err, kernel.ErrUnknownKernel) {
			t.Fatalf("Ensure(gost@\"\") = %v, want ErrUnknownKernel", err)
		}
	})
}

// TestOwnKernelsArmFallback covers the ARM key order: armv6 falls back to the
// armv5 row, armv7 keeps its own.
func TestOwnKernelsArmFallback(t *testing.T) {
	t.Run("armv6-uses-the-armv5-row", func(t *testing.T) {
		f := newFixture(t)
		own := newFileServer(t)
		plat := platform.Info{GOOS: "linux", GOARCH: "arm", ARM: 6, Libc: "musl"}
		ownTable(t, ownFrpRow(t, own, "0.71.1", "linux/armv5", "/frp-armv5.tar.gz", 64))
		in := ownInstaller(t, f, t.TempDir(), plat)

		inst, err := in.Ensure(context.Background(), pin("frp", ""))
		if err != nil {
			t.Fatalf("Ensure(frp@\"\") on armv6: %v", err)
		}
		if inst.Version != "0.71.1" {
			t.Fatalf("installed version = %q, want 0.71.1", inst.Version)
		}
		if n := own.hitCount("/frp-armv5.tar.gz"); n != 1 {
			t.Fatalf("the armv5 fallback asset hits = %d, want 1", n)
		}
	})

	t.Run("armv7-prefers-its-own-row", func(t *testing.T) {
		f := newFixture(t)
		own := newFileServer(t)
		plat := platform.Info{GOOS: "linux", GOARCH: "arm", ARM: 7, Libc: "musl"}
		ownTable(t,
			ownFrpRow(t, own, "0.71.1", "linux/armv5", "/frp-armv5.tar.gz", 64),
			ownFrpRow(t, own, "0.71.1", "linux/armv7", "/frp-armv7.tar.gz", 96),
		)
		in := ownInstaller(t, f, t.TempDir(), plat)

		inst, err := in.Ensure(context.Background(), pin("frp", "0.71.1"))
		if err != nil {
			t.Fatalf("Ensure(frp@0.71.1) on armv7: %v", err)
		}
		if inst.Version != "0.71.1" {
			t.Fatalf("installed version = %q, want 0.71.1", inst.Version)
		}
		if n := own.hitCount("/frp-armv7.tar.gz"); n != 1 {
			t.Fatalf("the armv7 asset hits = %d, want 1", n)
		}
		if n := own.hitCount("/frp-armv5.tar.gz"); n != 0 {
			t.Fatalf("the armv5 fallback was downloaded %d time(s)", n)
		}
	})
}

// TestOwnKernelsFrpInstallsBothMembers: the frp row is one tar.gz holding frpc
// and frps, and the result feeds driver/frp exactly like a manifest install.
func TestOwnKernelsFrpInstallsBothMembers(t *testing.T) {
	f := newFixture(t)
	own := newFileServer(t)
	ownTable(t, ownFrpRow(t, own, "0.71.1", "linux/amd64", "/frp.tar.gz", 64))
	in := ownInstaller(t, f, t.TempDir(), f.plat)

	inst, err := in.Ensure(context.Background(), pin("frp", "0.71.1"))
	if err != nil {
		t.Fatalf("Ensure(frp@0.71.1): %v", err)
	}
	if filepath.Base(inst.Path) != "frpc" {
		t.Fatalf("installed path = %q, want the frp run binary frpc", inst.Path)
	}
	frpsWant := filepath.Join(filepath.Dir(inst.Path), "frps")
	for _, p := range []string{inst.Path, frpsWant} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("installed binary missing: %v", err)
		}
	}
	frps, frpc, err := frp.Binaries(inst.Path)
	if err != nil {
		t.Fatalf("frp.Binaries(%q): %v", inst.Path, err)
	}
	if frps != frpsWant || frpc != inst.Path {
		t.Fatalf("Binaries = (%q, %q), want (%q, %q)", frps, frpc, frpsWant, inst.Path)
	}
}

// TestOwnKernelsIdempotentAndBackoff: the second Ensure is offline, a tampered
// install is downloaded again, and a verification failure backs off until an
// operator-initiated EnsureForce.
func TestOwnKernelsIdempotentAndBackoff(t *testing.T) {
	t.Run("second-ensure-is-offline", func(t *testing.T) {
		f := newFixture(t)
		own := newFileServer(t)
		ownTable(t, ownGzRow(t, own, "gost", "3.3.0", "linux/amd64", "", "/gost.gz", "3.3.0", 64))
		in := ownInstaller(t, f, t.TempDir(), f.plat)
		ctx := context.Background()

		first, err := in.Ensure(ctx, pin("gost", "3.3.0"))
		if err != nil {
			t.Fatalf("first Ensure: %v", err)
		}
		if n := own.hitCount("/gost.gz"); n != 1 {
			t.Fatalf("table asset hits = %d, want 1", n)
		}
		second, err := in.Ensure(ctx, pin("gost", "3.3.0"))
		if err != nil {
			t.Fatalf("second Ensure: %v", err)
		}
		if second.Path != first.Path || second.Version != first.Version {
			t.Fatalf("second Ensure = %+v, want %+v", second, first)
		}
		if n := own.hitCount("/gost.gz"); n != 1 {
			t.Fatalf("the second Ensure hit the network: %d request(s)", n)
		}
	})

	t.Run("tampered-file-is-downloaded-again", func(t *testing.T) {
		f := newFixture(t)
		own := newFileServer(t)
		ownTable(t, ownGzRow(t, own, "gost", "3.3.0", "linux/amd64", "", "/gost.gz", "3.3.0", 64))
		in := ownInstaller(t, f, t.TempDir(), f.plat)
		ctx := context.Background()

		inst, err := in.Ensure(ctx, pin("gost", "3.3.0"))
		if err != nil {
			t.Fatalf("first Ensure: %v", err)
		}
		tampered := append(fakeBin("3.3.0", 64), 'x')
		if err := os.WriteFile(inst.Path, tampered, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := in.Ensure(ctx, pin("gost", "3.3.0")); err != nil {
			t.Fatalf("Ensure after tampering: %v", err)
		}
		if n := own.hitCount("/gost.gz"); n != 2 {
			t.Fatalf("table asset hits = %d, want 2 (the tampered install must be downloaded again)", n)
		}
		got, err := os.ReadFile(inst.Path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, fakeBin("3.3.0", 64)) {
			t.Fatal("the tampered file was not replaced")
		}
	})

	t.Run("verify-failure-backs-off", func(t *testing.T) {
		f := newFixture(t)
		own := newFileServer(t)
		row := ownGzRow(t, own, "gost", "3.3.0", "linux/amd64", "", "/gost.gz", "3.3.0", 64)
		row.SHA256 = sum([]byte("not it"))
		ownTable(t, row)
		in := ownInstaller(t, f, t.TempDir(), f.plat)
		ctx := context.Background()

		_, err := in.Ensure(ctx, pin("gost", "3.3.0"))
		if got := kernel.Code(err); got != "verify_failed" {
			t.Fatalf("first Ensure = %v (code %q), want verify_failed", err, got)
		}
		if _, err := in.Ensure(ctx, pin("gost", "3.3.0")); !errors.Is(err, kernel.ErrBackoff) {
			t.Fatalf("second Ensure = %v, want ErrBackoff", err)
		}
		_, err = in.EnsureForce(ctx, pin("gost", "3.3.0"))
		if err == nil {
			t.Fatal("EnsureForce with a wrong sha256 succeeded")
		}
		if errors.Is(err, kernel.ErrBackoff) {
			t.Fatalf("EnsureForce was refused by the back-off: %v", err)
		}
		if got := kernel.Code(err); got != "verify_failed" {
			t.Fatalf("EnsureForce = %v (code %q), want a fresh verify_failed", err, got)
		}
	})
}

// TestOwnKernelsDisabledKeepsTheManifestPath: with the default Config the
// table is never consulted and a manifest-less install still fails closed.
func TestOwnKernelsDisabledKeepsTheManifestPath(t *testing.T) {
	f := newFixture(t)
	own := newFileServer(t)
	ownTable(t, ownGzRow(t, own, "gost", "3.3.0", "linux/amd64", "", "/gost.gz", "3.3.0", 64))
	in := f.installer(t.TempDir()) // OwnKernels stays false

	_, err := in.Ensure(context.Background(), pin("gost", "3.3.0"))
	if !errors.Is(err, kernel.ErrNoManifest) {
		t.Fatalf("Ensure(gost@3.3.0) = %v, want ErrNoManifest", err)
	}
	if n := own.hitCount("/gost.gz"); n != 0 {
		t.Fatalf("the built-in table was consulted with OwnKernels off: %d request(s)", n)
	}
}

// TestOwnKernelsOtherNamesUnchanged: xray and unknown names behave identically
// with the switch on and off, and never look at the table.
func TestOwnKernelsOtherNamesUnchanged(t *testing.T) {
	f := newFixture(t)
	own := newFileServer(t)
	ownTable(t, ownGzRow(t, own, "gost", "3.3.0", "linux/amd64", "", "/gost.gz", "3.3.0", 64))
	for _, tc := range []struct{ name, version string }{
		{"xray", "26.3.27"},
		{"nosuch", ""},
		{"nosuch", "1.0.0"},
	} {
		on := ownInstaller(t, f, t.TempDir(), f.plat)
		off := f.installer(t.TempDir())
		_, errOn := on.Ensure(context.Background(), pin(tc.name, tc.version))
		_, errOff := off.Ensure(context.Background(), pin(tc.name, tc.version))
		if kernel.Code(errOn) != kernel.Code(errOff) {
			t.Errorf("%s@%q: code with OwnKernels = %q, without = %q", tc.name, tc.version, kernel.Code(errOn), kernel.Code(errOff))
		}
		if errOn == nil {
			t.Errorf("%s@%q: succeeded without a manifest", tc.name, tc.version)
		}
	}
	if n := own.hitCount("/gost.gz"); n != 0 {
		t.Fatalf("the built-in table was consulted for another kernel: %d request(s)", n)
	}
}

var (
	reOwnURL = regexp.MustCompile(`^https://github\.com/W1nCwC/W1nCray/releases/download/(gost-v3\.3\.0|realm-v2\.9\.6|frp-v0\.71\.1)/W1nCray-(gost|realm|frp)-linux-[a-z0-9]+\.(gz|tar\.gz)$`)
	reOwnSHA = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// TestOwnKernelsGeneratedTable checks the generated data itself (the real
// ownkernels_gen.go, never a fixture): shape, counts, the null platforms and
// the variant samples.
func TestOwnKernelsGeneratedTable(t *testing.T) {
	if len(ownKernelTable) != 30 {
		t.Fatalf("the built-in table has %d rows, want 30", len(ownKernelTable))
	}
	count := map[string]int{}
	present := map[string]bool{}
	variants := map[string]string{}
	seen := map[string]bool{}
	for _, e := range ownKernelTable {
		count[e.Name]++
		present[e.Name+"@"+e.Platform] = true
		variants[e.Name+"@"+e.Platform] = e.Variant
		key := e.Name + "@" + e.Version + "@" + e.Platform
		if seen[key] {
			t.Errorf("duplicate row %s", key)
		}
		seen[key] = true
		if !strings.HasPrefix(e.Platform, "linux/") {
			t.Errorf("%s: platform %q is not a linux key", key, e.Platform)
		}
		m := reOwnURL.FindStringSubmatch(e.URL)
		if m == nil {
			t.Errorf("%s: URL %q is not a W1nCray release asset URL", key, e.URL)
		} else {
			if m[2] != e.Name || m[1] != e.Name+"-v"+e.Version {
				t.Errorf("%s: URL %q names release %q and kernel %q", key, e.URL, m[1], m[2])
			}
		}
		if !reOwnSHA.MatchString(e.SHA256) {
			t.Errorf("%s: sha256 %q is not 64 lowercase hex characters", key, e.SHA256)
		}
		if e.Size <= 0 {
			t.Errorf("%s: size %d, want > 0", key, e.Size)
		}
		wantArchive := manifest.ArchiveGz
		if e.Name == "frp" {
			wantArchive = manifest.ArchiveTarGz
		}
		if e.Archive != wantArchive {
			t.Errorf("%s: archive %q, want %q", key, e.Archive, wantArchive)
		}
		if e.Name == "frp" {
			want := []DirectMember{{From: "frpc", To: "frpc"}, {From: "frps", To: "frps"}}
			if len(e.Members) != len(want) || e.Members[0] != want[0] || e.Members[1] != want[1] {
				t.Errorf("%s: members %+v, want %+v", key, e.Members, want)
			}
		} else if len(e.Members) != 0 {
			t.Errorf("%s: unexpected members %+v", key, e.Members)
		}
	}
	for kernelName, want := range map[string]int{"gost": 12, "realm": 8, "frp": 10} {
		if count[kernelName] != want {
			t.Errorf("%s rows = %d, want %d", kernelName, count[kernelName], want)
		}
	}
	// The platforms the manifest marks null must not appear.
	for _, k := range []string{
		"realm@linux/386", "realm@linux/armv5", "realm@linux/loong64", "realm@linux/riscv64",
		"frp@linux/386", "frp@linux/armv6",
	} {
		if present[k] {
			t.Errorf("%s is null in the manifest but has a table row", k)
		}
	}
	for k, want := range map[string]string{
		"gost@linux/386":     "sse2",
		"realm@linux/mips":   "musl-full softfloat",
		"frp@linux/mips64le": "hardfloat",
	} {
		if variants[k] != want {
			t.Errorf("%s variant = %q, want %q", k, variants[k], want)
		}
	}
}
