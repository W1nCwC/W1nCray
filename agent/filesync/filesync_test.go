package filesync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// fakeFetcher serves blobs from memory and records what was asked for.
type fakeFetcher struct {
	mu        sync.Mutex
	blobs     map[string][]byte
	corrupt   map[string][]byte // served instead of the real content
	notMod    map[string]bool   // answer 304
	err       error
	downloads map[string]int
	bytes     int64
}

func newFakeFetcher() *fakeFetcher {
	return &fakeFetcher{
		blobs:     map[string][]byte{},
		corrupt:   map[string][]byte{},
		notMod:    map[string]bool{},
		downloads: map[string]int{},
	}
}

func (f *fakeFetcher) add(b []byte) string {
	sha := Digest(b)
	f.mu.Lock()
	f.blobs[sha] = b
	f.mu.Unlock()
	return sha
}

func (f *fakeFetcher) Fetch(_ context.Context, sha string) ([]byte, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.downloads[sha]++
	if f.err != nil {
		return nil, false, f.err
	}
	if f.notMod[sha] {
		return nil, true, nil
	}
	if b, ok := f.corrupt[sha]; ok {
		f.bytes += int64(len(b))
		return b, false, nil
	}
	b, ok := f.blobs[sha]
	if !ok {
		return nil, false, fmt.Errorf("no blob %s", sha)
	}
	f.bytes += int64(len(b))
	return b, false, nil
}

func (f *fakeFetcher) count(sha string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.downloads[sha]
}

func (f *fakeFetcher) totalBytes() int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.bytes
}

// stubValidator records the staged sets and answers with programmed errors.
type stubValidator struct {
	mu     sync.Mutex
	sets   [][]FileRef
	dirs   []string
	errs   []error
	errFor func(dir string, files []FileRef) []error
}

func (v *stubValidator) ValidateStaged(_ context.Context, dir string, files []FileRef) []error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.dirs = append(v.dirs, dir)
	v.sets = append(v.sets, append([]FileRef(nil), files...))
	if v.errFor != nil {
		return v.errFor(dir, files)
	}
	return v.errs
}

func (v *stubValidator) calls() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.sets)
}

func (v *stubValidator) lastSet() []FileRef {
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.sets) == 0 {
		return nil
	}
	return v.sets[len(v.sets)-1]
}

// stubReloader records the reload reasons and can refuse.
type stubReloader struct {
	mu      sync.Mutex
	reasons []string
	err     error
}

func (r *stubReloader) Reload(_ context.Context, reason string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reasons = append(r.reasons, reason)
	return r.err
}

func (r *stubReloader) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.reasons)
}

// rig is one applier with its temporary directories.
type rig struct {
	t        *testing.T
	config   string
	state    string
	fetch    *fakeFetcher
	validate *stubValidator
	reload   *stubReloader
	applier  *Applier
}

func newRig(t *testing.T) *rig {
	t.Helper()
	dir := t.TempDir()
	r := &rig{
		t:        t,
		config:   filepath.Join(dir, "xray"),
		state:    filepath.Join(dir, "state"),
		fetch:    newFakeFetcher(),
		validate: &stubValidator{},
		reload:   &stubReloader{},
	}
	if err := os.MkdirAll(r.config, 0o755); err != nil {
		t.Fatal(err)
	}
	a, err := New(Options{
		ConfigDir:       r.config,
		StateDir:        r.state,
		Fetch:           r.fetch,
		Validate:        r.validate,
		Reload:          r.reload,
		LayoutSeparated: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r.applier = a
	return r
}

// ref publishes content and returns the FileRef the panel would send.
func (r *rig) ref(name string, content []byte) FileRef {
	r.t.Helper()
	sha := r.fetch.add(content)
	return FileRef{Name: name, SHA256: sha, Size: int64(len(content))}
}

// write puts content in the xray directory (the state before an apply).
func (r *rig) write(name string, content []byte) {
	r.t.Helper()
	if err := os.WriteFile(filepath.Join(r.config, name), content, 0o644); err != nil {
		r.t.Fatal(err)
	}
}

// read returns the current content of a managed file.
func (r *rig) read(name string) string {
	r.t.Helper()
	b, err := os.ReadFile(filepath.Join(r.config, name))
	if err != nil {
		r.t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

func (r *rig) exists(name string) bool {
	_, err := os.Stat(filepath.Join(r.config, name))
	return err == nil
}

func (r *rig) shaOf(name string) string {
	r.t.Helper()
	b, err := os.ReadFile(filepath.Join(r.config, name))
	if err != nil {
		r.t.Fatalf("read %s: %v", name, err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ---- whitelist (acceptance 3) ----------------------------------------------

// TestCheckNameRefusesEverythingOutsideTheWhitelist covers acceptance 3: a
// traversal, an absolute path, the agent's own configuration and the agent's
// state files are all refused, with no directory separator ever accepted.
func TestCheckNameRefusesEverythingOutsideTheWhitelist(t *testing.T) {
	bad := []string{
		"", "../evil", "../../etc/passwd", "..", "route.json/../evil",
		"/etc/passwd", `C:\Windows\System32\evil.dll`, "sub/route.json",
		`sub\route.json`, "agent.yml", "AGENT.YML", "desired.json", "last_good.json",
		"blocked.json", "manifest.json", "other.json", "geoip.dat.bak", "route.json ",
	}
	for _, name := range bad {
		if err := CheckName(name); err == nil {
			t.Errorf("CheckName(%q) accepted a name outside the whitelist", name)
		}
		if IsManaged(name) {
			t.Errorf("IsManaged(%q) = true", name)
		}
	}
	for _, name := range ManagedNames {
		if err := CheckName(name); err != nil {
			t.Errorf("CheckName(%q) = %v, want nil", name, err)
		}
		if !IsManaged(name) {
			t.Errorf("IsManaged(%q) = false", name)
		}
	}
}

// TestApplyRefusesNamesOutsideTheWhitelist covers acceptance 3 end to end: a
// bad name is refused before anything is downloaded, staged or replaced.
func TestApplyRefusesNamesOutsideTheWhitelist(t *testing.T) {
	for _, name := range []string{"../evil", "/etc/passwd", "agent.yml", "unknown.json"} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.write(NameRoute, []byte(`{"rules":[]}`))
			before := r.shaOf(NameRoute)

			res, err := r.applier.Apply(context.Background(), []FileRef{
				{Name: name, SHA256: strings.Repeat("a", 64), Size: 3},
			})
			if err != nil {
				t.Fatalf("Apply: %v", err)
			}
			if res.Status != StatusFailed {
				t.Fatalf("status = %q, want failed", res.Status)
			}
			if len(res.Errors) == 0 || !strings.Contains(res.Errors[0], name) {
				t.Errorf("errors = %v, want one naming %q", res.Errors, name)
			}
			if got := r.shaOf(NameRoute); got != before {
				t.Error("a managed file was replaced although the name was refused")
			}
			if r.validate.calls() != 0 {
				t.Error("validation ran although the name was refused")
			}
			if r.reload.count() != 0 {
				t.Error("the instance was reloaded although the name was refused")
			}
		})
	}
}

// TestApplyRefusesConfigYMLWithoutTheSeparatedLayout covers ruling 2: with the
// agent's own configuration still in config.yml, the panel may not write it.
func TestApplyRefusesConfigYMLWithoutTheSeparatedLayout(t *testing.T) {
	r := newRig(t)
	a, err := New(Options{
		ConfigDir:       r.config,
		StateDir:        r.state,
		Fetch:           r.fetch,
		Validate:        r.validate,
		Reload:          r.reload,
		LayoutSeparated: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := a.Apply(context.Background(), []FileRef{r.ref(NameConfig, []byte("Log: {}\n"))})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Status != StatusFailed {
		t.Fatalf("status = %q, want failed", res.Status)
	}
	if !strings.Contains(strings.Join(res.Errors, " "), "still lives in config.yml") {
		t.Errorf("errors = %v, want the layout refusal", res.Errors)
	}
	if r.exists(NameConfig) {
		t.Error("config.yml was written although the layout is not separated")
	}
	if r.fetch.totalBytes() != 0 {
		t.Error("a blob was downloaded for a refused config.yml")
	}
}

// ---- blob verification (acceptance 2) --------------------------------------

// TestApplyRefusesASha256Mismatch covers acceptance 2: a body that does not
// hash back to the requested digest is neither cached nor replaced.
func TestApplyRefusesASha256Mismatch(t *testing.T) {
	r := newRig(t)
	old := []byte(`{"rules":[]}`)
	r.write(NameRoute, old)
	before := r.shaOf(NameRoute)

	want := r.ref(NameRoute, []byte(`{"rules":[{"outboundTag":"direct"}]}`))
	r.fetch.mu.Lock()
	r.fetch.corrupt[want.SHA256] = []byte(`{"rules":[{"outboundTag":"evil"}]}`)
	r.fetch.mu.Unlock()

	res, err := r.applier.Apply(context.Background(), []FileRef{want})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Status != StatusFailed {
		t.Fatalf("status = %q, want failed", res.Status)
	}
	if !strings.Contains(strings.Join(res.Errors, " "), "sha256 mismatch") {
		t.Errorf("errors = %v, want a sha256 mismatch", res.Errors)
	}
	if got := r.shaOf(NameRoute); got != before {
		t.Error("route.json was replaced although its content did not hash back")
	}
	if _, ok := r.applier.store.Get(want.SHA256); ok {
		t.Error("a blob that failed its hash check was cached")
	}
	if r.validate.calls() != 0 {
		t.Error("validation ran on an unverified blob")
	}
}

// TestApplyRefusesASizeMismatch: the declared size is checked too, so a panel
// that lies about the length is caught even when the hash matches.
func TestApplyRefusesASizeMismatch(t *testing.T) {
	r := newRig(t)
	r.write(NameRoute, []byte(`{"rules":[]}`))
	before := r.shaOf(NameRoute)

	ref := r.ref(NameRoute, []byte(`{"rules":[]}`))
	ref.Size = 9999
	res, err := r.applier.Apply(context.Background(), []FileRef{ref})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Status != StatusFailed || !strings.Contains(strings.Join(res.Errors, " "), "size mismatch") {
		t.Fatalf("res = %+v, want a size mismatch", res)
	}
	if got := r.shaOf(NameRoute); got != before {
		t.Error("route.json was replaced although the size did not match")
	}
}

// TestApplyRefusesANonDigestAddress: a sha256 that is not a digest never
// reaches the fetcher.
func TestApplyRefusesANonDigestAddress(t *testing.T) {
	r := newRig(t)
	res, err := r.applier.Apply(context.Background(), []FileRef{{Name: NameRoute, SHA256: "../../etc/passwd", Size: 1}})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Status != StatusFailed {
		t.Fatalf("status = %q, want failed", res.Status)
	}
	if r.fetch.totalBytes() != 0 {
		t.Error("a blob was fetched for a non-digest address")
	}
}

// TestApplyRefusesABlobOverTheLimit: the per-file limit is enforced before the
// content is cached.
func TestApplyRefusesABlobOverTheLimit(t *testing.T) {
	r := newRig(t)
	big := []byte(strings.Repeat("g", 4096))
	ref := r.ref(NameGeoIP, big)
	a, err := New(Options{
		ConfigDir: r.config, StateDir: r.state,
		Fetch: r.fetch, Validate: r.validate, Reload: r.reload,
		MaxBytes: 1024, LayoutSeparated: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := a.Apply(context.Background(), []FileRef{ref})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Status != StatusFailed || !strings.Contains(strings.Join(res.Errors, " "), "over the") {
		t.Fatalf("res = %+v, want an over-limit failure", res)
	}
	if _, ok := r.applier.store.Get(ref.SHA256); ok {
		t.Error("an over-limit blob was cached")
	}
	if r.exists(NameGeoIP) {
		t.Error("geoip.dat was written although its blob was over the limit")
	}
}

// TestApplyRefusesGeoFilesDisabledByLocalPolicy: MaxBytes < 0 is the OpenWrt
// default; the refusal must be explicit, never a silent skip.
func TestApplyRefusesGeoFilesDisabledByLocalPolicy(t *testing.T) {
	r := newRig(t)
	a, err := New(Options{
		ConfigDir: r.config, StateDir: r.state,
		Fetch: r.fetch, Validate: r.validate, Reload: r.reload,
		MaxBytes: -1, LayoutSeparated: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := a.Apply(context.Background(), []FileRef{r.ref(NameGeoIP, []byte("geo"))})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Status != StatusFailed || !strings.Contains(strings.Join(res.Errors, " "), "geo files disabled by local policy") {
		t.Fatalf("res = %+v, want an explicit local-policy refusal", res)
	}
	if r.fetch.totalBytes() != 0 {
		t.Error("a geo blob was downloaded although geo files are disabled locally")
	}
}

// ---- validation (acceptance 4 and 5) ---------------------------------------

// TestApplyValidationRefusalChangesNothing covers acceptance 4: when the staged
// route.json is refused, the file on disk is untouched, nothing is reloaded and
// the error carries the file name and the rule index.
func TestApplyValidationRefusalChangesNothing(t *testing.T) {
	r := newRig(t)
	old := []byte(`{"rules":[]}`)
	r.write(NameRoute, old)
	before := r.shaOf(NameRoute)

	ref := r.ref(NameRoute, []byte(`{"rules":[{"not":"a rule"}]}`))
	r.validate.errFor = func(_ string, files []FileRef) []error {
		if len(files) != 1 || files[0].Name != NameRoute {
			t.Errorf("validator saw %v", files)
		}
		return []error{fmt.Errorf("%s: rules[0] unknown field", NameRoute)}
	}
	res, err := r.applier.Apply(context.Background(), []FileRef{ref})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Status != StatusInvalid {
		t.Fatalf("status = %q, want invalid", res.Status)
	}
	if len(res.Errors) != 1 || !strings.Contains(res.Errors[0], "route.json") || !strings.Contains(res.Errors[0], "rules[0]") {
		t.Errorf("errors = %v, want the file name and the rule index", res.Errors)
	}
	if got := r.shaOf(NameRoute); got != before {
		t.Error("route.json was replaced although validation refused it")
	}
	if r.reload.count() != 0 {
		t.Error("the instance was reloaded although validation refused the files")
	}
	if r.applier.store.HasLastGood() {
		t.Error("a last_good snapshot was taken for a refused set")
	}
	// The staged copy must not survive the refusal.
	if entries, err := os.ReadDir(filepath.Join(r.state, stageDirName)); err == nil {
		for _, e := range entries {
			t.Errorf("staging directory %s survived the refusal", e.Name())
		}
	}
}

// TestValidateCommandWritesNothing covers the files_validate command: it stages
// and validates, and never touches a managed file or the instance.
func TestValidateCommandWritesNothing(t *testing.T) {
	r := newRig(t)
	old := []byte(`{"rules":[]}`)
	r.write(NameRoute, old)
	before := r.shaOf(NameRoute)
	ref := r.ref(NameRoute, []byte(`{"rules":[{"outboundTag":"direct"}]}`))
	a, err := New(Options{
		ConfigDir: r.config, StateDir: r.state,
		Fetch: r.fetch, Validate: r.validate, Reload: r.reload,
		LayoutSeparated: true,
		Source:          SourceFunc(func() []FileRef { return []FileRef{ref} }),
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := a.Validate(context.Background())
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Status != StatusDone {
		t.Fatalf("status = %q, want done", res.Status)
	}
	if got := r.shaOf(NameRoute); got != before {
		t.Error("files_validate wrote a managed file")
	}
	if r.reload.count() != 0 {
		t.Error("files_validate reloaded the instance")
	}
	if r.validate.calls() != 1 {
		t.Errorf("validator calls = %d, want 1", r.validate.calls())
	}

	// A refusal is reported, and still nothing is written.
	r.validate.errFor = func(string, []FileRef) []error { return []error{errors.New("route.json: rules[0] bad")} }
	res, err = a.Validate(context.Background())
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Status != StatusInvalid {
		t.Fatalf("status = %q, want invalid", res.Status)
	}
	if got := r.shaOf(NameRoute); got != before {
		t.Error("files_validate wrote a managed file after a refusal")
	}
}

// ---- happy path and idempotency (acceptance 6) -----------------------------

// TestApplyReplacesReloadsAndIsIdempotent covers acceptance 6: the files are
// replaced, the reload is initiated, applied.json is written, and a second call
// with the same sha256 downloads nothing and does not reload again.
func TestApplyReplacesReloadsAndIsIdempotent(t *testing.T) {
	r := newRig(t)
	r.write(NameRoute, []byte(`{"rules":[]}`))
	r.write(NameDNS, []byte(`{"servers":["localhost"]}`))

	route := r.ref(NameRoute, []byte(`{"rules":[{"outboundTag":"direct"}]}`))
	dns := r.ref(NameDNS, []byte(`{"servers":["1.1.1.1"]}`))

	res, err := r.applier.Apply(context.Background(), []FileRef{route, dns})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Status != StatusDone || res.Reload != ReloadReloaded {
		t.Fatalf("res = %+v, want done/reloaded", res)
	}
	if got := r.shaOf(NameRoute); got != route.SHA256 {
		t.Error("route.json was not replaced")
	}
	if got := r.shaOf(NameDNS); got != dns.SHA256 {
		t.Error("dns.json was not replaced")
	}
	if r.reload.count() != 1 {
		t.Errorf("reloads = %d, want 1", r.reload.count())
	}
	// The snapshot of the previous files is kept: it is what a later
	// files_rollback (or a reload refusal) restores.
	if !r.applier.store.HasLastGood() {
		t.Error("last_good was dropped although it is needed for a later rollback")
	}
	// applied.json records the set.
	if _, err := os.Stat(filepath.Join(r.state, appliedName)); err != nil {
		t.Errorf("applied.json: %v", err)
	}
	bytesFirst := r.fetch.totalBytes()
	if bytesFirst == 0 {
		t.Error("nothing was downloaded on the first apply")
	}

	// Second call with the same content: no download, no replacement, no
	// reload.
	res2, err := r.applier.Apply(context.Background(), []FileRef{route, dns})
	if err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	if res2.Status != StatusDone || res2.Reload != ReloadNotNeeded {
		t.Fatalf("second res = %+v, want done/not_needed", res2)
	}
	for _, f := range res2.Files {
		if !f.Skipped || f.Bytes != 0 {
			t.Errorf("second apply file %+v, want skipped with 0 bytes", f)
		}
	}
	if r.fetch.totalBytes() != bytesFirst {
		t.Error("the second apply downloaded a blob again")
	}
	if r.reload.count() != 1 {
		t.Errorf("reloads = %d, want still 1", r.reload.count())
	}
	if r.validate.calls() != 1 {
		t.Errorf("validator calls = %d, want still 1", r.validate.calls())
	}
}

// TestApplyUsesTheBlobCacheForANewName: the same bytes under a different
// revision are served from the cache, so nothing is transferred twice.
func TestApplyUsesTheBlobCacheForANewName(t *testing.T) {
	r := newRig(t)
	route := r.ref(NameRoute, []byte(`{"rules":[{"outboundTag":"direct"}]}`))
	if _, err := r.applier.Apply(context.Background(), []FileRef{route}); err != nil {
		t.Fatal(err)
	}
	first := r.fetch.totalBytes()

	// A second apply of the same content (the on-disk copy was changed behind
	// the agent's back, so it has to be staged again) must come from the cache.
	r.write(NameRoute, []byte(`{"rules":[]}`))
	res, err := r.applier.Apply(context.Background(), []FileRef{route})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusDone {
		t.Fatalf("res = %+v", res)
	}
	if r.fetch.totalBytes() != first {
		t.Error("the blob was downloaded again although it was cached")
	}
	for _, f := range res.Files {
		if f.Bytes != 0 {
			t.Errorf("file %+v reports bytes although it came from the cache", f)
		}
	}
}

// ---- geo-only changes (acceptance 8) ---------------------------------------

// TestGeoOnlyChangeDoesNotReload covers acceptance 8: replacing geoip.dat is a
// pure file swap with reload "not_needed".
func TestGeoOnlyChangeDoesNotReload(t *testing.T) {
	r := newRig(t)
	r.write(NameGeoIP, []byte("old geo"))
	r.write(NameRoute, []byte(`{"rules":[]}`))
	routeBefore := r.shaOf(NameRoute)

	geo := r.ref(NameGeoIP, []byte("new geo database"))
	res, err := r.applier.Apply(context.Background(), []FileRef{geo})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Status != StatusDone || res.Reload != ReloadNotNeeded {
		t.Fatalf("res = %+v, want done/not_needed", res)
	}
	if r.reload.count() != 0 {
		t.Error("a geo-only change reloaded the instance")
	}
	if got := r.shaOf(NameGeoIP); got != geo.SHA256 {
		t.Error("geoip.dat was not replaced")
	}
	if got := r.shaOf(NameRoute); got != routeBefore {
		t.Error("route.json changed although it was not part of the set")
	}
	// The geo database is still a managed file: it goes through the staged
	// pre-check (which only hashes it), it just does not trigger a reload.
	if r.validate.calls() != 1 {
		t.Errorf("validator calls = %d, want 1 (the staged geo file)", r.validate.calls())
	}
}

// ---- rollback (acceptance 7) -----------------------------------------------

// TestReloadRefusalRestoresLastGood covers acceptance 7: when the reload is
// refused (the configuration would not come back up), the previous files are
// restored and the result says so.
func TestReloadRefusalRestoresLastGood(t *testing.T) {
	r := newRig(t)
	oldRoute := []byte(`{"rules":[]}`)
	oldDNS := []byte(`{"servers":["localhost"]}`)
	r.write(NameRoute, oldRoute)
	r.write(NameDNS, oldDNS)
	routeBefore, dnsBefore := r.shaOf(NameRoute), r.shaOf(NameDNS)

	r.reload.err = errors.New("reload refused, the running config is kept: config.yml: no Nodes configured")
	route := r.ref(NameRoute, []byte(`{"rules":[{"outboundTag":"direct"}]}`))
	dns := r.ref(NameDNS, []byte(`{"servers":["1.1.1.1"]}`))

	res, err := r.applier.Apply(context.Background(), []FileRef{route, dns})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Status != StatusRolledBack || !res.RolledBack {
		t.Fatalf("res = %+v, want a rollback", res)
	}
	if res.Reload != ReloadFailed {
		t.Errorf("reload = %q, want failed", res.Reload)
	}
	if !strings.Contains(res.Reason, "reload refused") {
		t.Errorf("reason = %q", res.Reason)
	}
	if got := r.shaOf(NameRoute); got != routeBefore {
		t.Error("route.json was not restored from last_good")
	}
	if got := r.shaOf(NameDNS); got != dnsBefore {
		t.Error("dns.json was not restored from last_good")
	}
}

// TestRollbackCommandRestoresAndReloads covers the files_rollback command: the
// last_good set is restored and the instance is reloaded with a reason.
func TestRollbackCommandRestoresAndReloads(t *testing.T) {
	r := newRig(t)
	oldRoute := []byte(`{"rules":[]}`)
	r.write(NameRoute, oldRoute)
	routeBefore := r.shaOf(NameRoute)

	// Apply a new route.json, then roll it back.
	route := r.ref(NameRoute, []byte(`{"rules":[{"outboundTag":"direct"}]}`))
	if _, err := r.applier.Apply(context.Background(), []FileRef{route}); err != nil {
		t.Fatal(err)
	}
	if r.shaOf(NameRoute) == routeBefore {
		t.Fatal("the apply did not change route.json")
	}
	res, err := r.applier.Rollback(context.Background())
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if res.Status != StatusRolledBack || !res.RolledBack {
		t.Fatalf("res = %+v", res)
	}
	if got := r.shaOf(NameRoute); got != routeBefore {
		t.Error("route.json was not restored")
	}
	if r.reload.count() != 2 {
		t.Errorf("reloads = %d, want 2 (apply + rollback)", r.reload.count())
	}
	if r.reload.reasons[1] != ReasonRollback {
		t.Errorf("rollback reason = %q", r.reload.reasons[1])
	}
	if _, err := r.applier.Rollback(context.Background()); err == nil {
		t.Error("a second rollback must fail: there is nothing left to restore")
	}
}

// TestRollbackRemovesFilesTheSnapshotDidNotHave: a managed file that did not
// exist when the snapshot was taken is removed again, so a rollback never
// leaves a half-applied set behind.
func TestRollbackRemovesFilesTheSnapshotDidNotHave(t *testing.T) {
	r := newRig(t)
	// geoip.dat does not exist yet; the snapshot records that.
	geo := r.ref(NameGeoIP, []byte("geo bytes"))
	if _, err := r.applier.Apply(context.Background(), []FileRef{geo}); err != nil {
		t.Fatal(err)
	}
	if !r.exists(NameGeoIP) {
		t.Fatal("the apply did not create geoip.dat")
	}
	if _, err := r.applier.Rollback(context.Background()); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if r.exists(NameGeoIP) {
		t.Error("the rollback left a file that did not exist before the apply")
	}
}

// ---- modes and last_good ---------------------------------------------------

// TestReplacementKeepsTheExistingMode: an operator who chmodded a managed file
// keeps that mode across an apply. Windows reports synthetic permission bits
// (only the read-only attribute is real), so the check is Unix-only.
func TestReplacementKeepsTheExistingMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not report real Unix permission bits")
	}
	r := newRig(t)
	p := filepath.Join(r.config, NameGeoIP)
	if err := os.WriteFile(p, []byte("old"), 0o640); err != nil {
		t.Fatal(err)
	}
	geo := r.ref(NameGeoIP, []byte("new"))
	if _, err := r.applier.Apply(context.Background(), []FileRef{geo}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o640 {
		t.Errorf("mode = %04o, want 0640", fi.Mode().Perm())
	}
}

// TestSnapshotAndRestoreLastGoodRoundTrip covers the store primitive directly.
func TestSnapshotAndRestoreLastGoodRoundTrip(t *testing.T) {
	r := newRig(t)
	r.write(NameRoute, []byte("v1"))
	r.write(NameDNS, []byte("v1 dns"))
	if err := r.applier.store.SnapshotLastGood(r.config, []string{NameRoute, NameDNS, NameGeoIP}); err != nil {
		t.Fatalf("SnapshotLastGood: %v", err)
	}
	if !r.applier.store.HasLastGood() {
		t.Fatal("no snapshot")
	}
	r.write(NameRoute, []byte("v2"))
	if err := os.Remove(filepath.Join(r.config, NameDNS)); err != nil {
		t.Fatal(err)
	}
	r.write(NameGeoIP, []byte("created"))
	names, err := r.applier.store.RestoreLastGood(r.config)
	if err != nil {
		t.Fatalf("RestoreLastGood: %v", err)
	}
	if len(names) != 2 {
		t.Errorf("restored names = %v, want the two that existed", names)
	}
	if got := r.read(NameRoute); got != "v1" {
		t.Errorf("route.json = %q, want v1", got)
	}
	if got := r.read(NameDNS); got != "v1 dns" {
		t.Errorf("dns.json = %q, want the snapshot back", got)
	}
	if r.exists(NameGeoIP) {
		t.Error("geoip.dat was not removed by the rollback")
	}
}

// TestStageBlobRefusesABadName: the staging directory can only ever contain
// whitelisted names.
func TestStageBlobRefusesABadName(t *testing.T) {
	r := newRig(t)
	sha := r.fetch.add([]byte("x"))
	if _, err := r.applier.store.Put(sha, []byte("x")); err != nil {
		t.Fatal(err)
	}
	stage, err := r.applier.store.NewStage()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.applier.store.DiscardStage(stage) }()
	if err := r.applier.store.StageBlob(stage, "../evil", sha); err == nil {
		t.Error("StageBlob accepted a traversal name")
	}
	if err := r.applier.store.StageBlob(stage, NameRoute, sha); err != nil {
		t.Errorf("StageBlob(%s) = %v", NameRoute, err)
	}
}

// TestStoreBlobCacheIsContentAddressed: Put/Get/Has key on the digest, and a
// second Put of the same digest is a no-op.
func TestStoreBlobCacheIsContentAddressed(t *testing.T) {
	r := newRig(t)
	sha := Digest([]byte("content"))
	p, err := r.applier.store.Put(sha, []byte("content"))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if filepath.Base(p) != sha {
		t.Errorf("blob path = %q, want the digest", p)
	}
	if !r.applier.store.Has(sha) {
		t.Error("Has = false after Put")
	}
	if got, ok := r.applier.store.Get(sha); !ok || got != p {
		t.Errorf("Get = %q,%v want %q,true", got, ok, p)
	}
	if _, err := r.applier.store.Put("not-a-digest", []byte("x")); err == nil {
		t.Error("Put accepted a non-digest name")
	}
	if r.applier.store.Has("../evil") {
		t.Error("Has accepted a traversal name")
	}
}

// TestApplyRefusesAnEmptyFileSet: an empty desired file set is a protocol
// error, never "apply nothing".
func TestApplyRefusesAnEmptyFileSet(t *testing.T) {
	r := newRig(t)
	if _, err := r.applier.Apply(context.Background(), nil); err == nil {
		t.Error("an empty file set was accepted")
	}
	if r.validate.calls() != 0 || r.reload.count() != 0 {
		t.Error("an empty file set reached the validator or the reloader")
	}
}

// TestApplyRefusesADuplicateName: the same managed file twice is a protocol
// error, not a race between two replacements.
func TestApplyRefusesADuplicateName(t *testing.T) {
	r := newRig(t)
	ref := r.ref(NameRoute, []byte(`{"rules":[]}`))
	res, err := r.applier.Apply(context.Background(), []FileRef{ref, ref})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Status != StatusFailed || !strings.Contains(strings.Join(res.Errors, " "), "twice") {
		t.Fatalf("res = %+v", res)
	}
	if r.fetch.totalBytes() != 0 {
		t.Error("a blob was fetched for a duplicate-name set")
	}
}

// TestApplyReportsAFetchFailure: a panel that cannot serve the blob fails the
// apply without touching the files.
func TestApplyReportsAFetchFailure(t *testing.T) {
	r := newRig(t)
	r.write(NameRoute, []byte(`{"rules":[]}`))
	before := r.shaOf(NameRoute)
	ref := FileRef{Name: NameRoute, SHA256: strings.Repeat("b", 64), Size: 10}
	r.fetch.err = errors.New("panel unreachable")

	res, err := r.applier.Apply(context.Background(), []FileRef{ref})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Status != StatusFailed || !strings.Contains(strings.Join(res.Errors, " "), "panel unreachable") {
		t.Fatalf("res = %+v", res)
	}
	if got := r.shaOf(NameRoute); got != before {
		t.Error("route.json changed although the blob could not be fetched")
	}
}

// TestUnwiredApplierRefusesClearly: before the panel link exists the applier has
// no fetcher, and a call must fail with a clear message instead of a panic.
func TestUnwiredApplierRefusesClearly(t *testing.T) {
	r := newRig(t)
	a, err := New(Options{
		ConfigDir: r.config, StateDir: filepath.Join(r.state, "unwired"),
		Fetch: filesyncNoFetch{}, Validate: r.validate, LayoutSeparated: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ref := FileRef{Name: NameRoute, SHA256: strings.Repeat("c", 64), Size: 2}
	res, err := a.Apply(context.Background(), []FileRef{ref})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Status != StatusFailed || !strings.Contains(strings.Join(res.Errors, " "), "no blob can be fetched") {
		t.Fatalf("res = %+v", res)
	}
}

// filesyncNoFetch is a fetcher that refuses everything, standing in for the
// window between Boot and the panel link.
type filesyncNoFetch struct{}

func (filesyncNoFetch) Fetch(context.Context, string) ([]byte, bool, error) {
	return nil, false, errors.New("filesync: no blob can be fetched")
}

// TestApplyPrunesOldStagingDirectories: a crashed apply must not leave staged
// bytes behind forever.
func TestApplyPrunesOldStagingDirectories(t *testing.T) {
	r := newRig(t)
	old, err := r.applier.store.NewStage()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(old, NameRoute), []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	ref := r.ref(NameRoute, []byte(`{"rules":[]}`))
	if _, err := r.applier.Apply(context.Background(), []FileRef{ref}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(old); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the old staging directory survived: %v", err)
	}
}
