// Package manifest defines the signed kernel manifest: the only trust root
// the agent accepts for external kernel binaries. See package kernel for the
// trust model and the field reference.
package manifest

import (
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/W1nCwC/W1nCray/kernel"
)

// SchemaVersion is the only manifest schema this code understands. A newer
// schema is rejected (fail-closed) instead of being half-interpreted.
const SchemaVersion = 1

// Archive formats.
const (
	ArchiveTarGz = "tar.gz"
	ArchiveZip   = "zip"
)

// Limits applied to everything a manifest may describe.
const (
	MaxManifestBytes = 8 << 20
	MaxArchiveBytes  = 1 << 30 // largest archive_size accepted
	MaxExtractBytes  = 1 << 30 // largest single extracted file
	MaxURLs          = 8
	MaxExtractFiles  = 16
)

// Manifest is the signed document. Version strings never carry a leading
// "v" (normalise with NormalizeVersion).
type Manifest struct {
	Schema    int        `json:"schema"`
	Sequence  int64      `json:"sequence"` // strictly monotonic per signing key lineage
	IssuedAt  time.Time  `json:"issued_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	Kernels   []Kernel   `json:"kernels"`
	Signature *Signature `json:"signature,omitempty"`
}

// Signature is detached from the signed bytes: it covers the canonical JSON
// of the document without this field.
type Signature struct {
	Alg   string `json:"alg"`    // "ed25519"
	KeyID string `json:"key_id"` // KeyID of the signing key
	Sig   string `json:"sig"`    // base64 (std) ed25519 signature
}

// Kernel is one name+version entry.
type Kernel struct {
	Name     string  `json:"name"`
	Version  string  `json:"version"`
	Channel  string  `json:"channel,omitempty"` // stable | beta | ...
	MinAgent string  `json:"min_agent,omitempty"`
	License  License `json:"license"`
	// Capabilities is free-form data shown by the panel; the agent never
	// interprets it.
	Capabilities map[string]any `json:"capabilities,omitempty"`
	Run          Run            `json:"run"`
	// Targets maps a platform key ("linux/amd64", "linux/mipsle",
	// "linux/armv7", ...) to a build. A key present with a null value means
	// "no build exists for that platform"; a missing key means the manifest
	// says nothing about it. Both make the kernel unavailable there, but
	// callers can tell them apart with Kernel.Lookup.
	Targets map[string]*Target `json:"targets"`
	Revoked []Revocation       `json:"revoked,omitempty"`
}

// License records what a mirror must ship alongside the binary.
type License struct {
	SPDX      string `json:"spdx"`
	File      string `json:"file,omitempty"` // license file name inside the archive
	SourceURL string `json:"source_url,omitempty"`
}

// Run describes how to run the post-install self-check.
type Run struct {
	// Binary is the "to" name of the main executable among Target.Extract.
	Binary string `json:"binary"`
	// VersionCmd are the arguments passed to Binary (never a shell string).
	VersionCmd []string `json:"version_cmd"`
	// VersionRegex optionally extracts the version from the combined output
	// (one capture group). Default: first dotted number sequence.
	VersionRegex string `json:"version_regex,omitempty"`
}

// Target is one downloadable build.
type Target struct {
	Variant       string    `json:"variant,omitempty"` // softfloat | hardfloat | sse2 | musl-full | glibc ...
	URLs          []string  `json:"urls"`              // ordered transport sources; hashes decide trust
	Archive       string    `json:"archive"`           // tar.gz | zip
	ArchiveSHA256 string    `json:"archive_sha256"`
	ArchiveSize   int64     `json:"archive_size"`
	Extract       []Extract `json:"extract"`
	InstalledSize int64     `json:"installed_size,omitempty"`
}

// Extract names one file to take out of the archive. Only listed files are
// ever written; Mode comes from here, never from the archive.
type Extract struct {
	From   string `json:"from"`   // path inside the archive
	To     string `json:"to"`     // plain file name in the version directory
	SHA256 string `json:"sha256"` // of the extracted content
	Size   int64  `json:"size"`
	Mode   string `json:"mode"` // octal string, e.g. "0755"
}

// Revocation revokes a version and/or a content hash. Revocations of any
// entry apply to every entry of the same kernel name; a revoked sha256
// matches archive_sha256 and extract sha256 of any kernel.
type Revocation struct {
	Version string `json:"version,omitempty"`
	SHA256  string `json:"sha256,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

var (
	reName    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	reVersion = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$`)
	reTarget  = regexp.MustCompile(`^[a-z0-9]{2,16}/[a-z0-9]{2,16}$`)
	reSHA256  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	reFile    = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,63}$`)
)

// reservedNames are file names the installer uses inside a version directory.
var reservedNames = map[string]bool{".installed.json": true}

// NormalizeVersion strips a leading "v"/"V" so panel pins ("v3.3.0") and
// manifest versions ("3.3.0") compare equal.
func NormalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > 1 && (v[0] == 'v' || v[0] == 'V') && v[1] >= '0' && v[1] <= '9' {
		return v[1:]
	}
	return v
}

func invalid(format string, args ...any) error {
	return kernel.Newf(kernel.ErrManifestInvalid, "", "", format, args...)
}

// Validate checks the structure and every limit. It does not look at the
// signature, clock or sequence (see Verify).
func (m *Manifest) Validate() error {
	if m.Schema != SchemaVersion {
		return invalid("unsupported schema %d (want %d)", m.Schema, SchemaVersion)
	}
	if m.Sequence <= 0 {
		return invalid("sequence must be positive")
	}
	if m.IssuedAt.IsZero() || m.ExpiresAt.IsZero() {
		return invalid("issued_at and expires_at are required")
	}
	if !m.ExpiresAt.After(m.IssuedAt) {
		return invalid("expires_at must be after issued_at")
	}
	if len(m.Kernels) == 0 {
		return invalid("no kernels")
	}
	seen := map[string]bool{}
	for i := range m.Kernels {
		k := &m.Kernels[i]
		if err := k.validate(); err != nil {
			return err
		}
		id := k.Name + "@" + k.Version
		if seen[id] {
			return invalid("duplicate kernel entry %s", id)
		}
		seen[id] = true
	}
	return nil
}

func (k *Kernel) validate() error {
	id := k.Name + "@" + k.Version
	if !reName.MatchString(k.Name) {
		return invalid("kernel name %q invalid", k.Name)
	}
	if !reVersion.MatchString(k.Version) || NormalizeVersion(k.Version) != k.Version {
		return invalid("%s: version invalid (must not start with v)", id)
	}
	if k.MinAgent != "" && !reVersion.MatchString(NormalizeVersion(k.MinAgent)) {
		return invalid("%s: min_agent invalid", id)
	}
	if k.License.SPDX == "" {
		return invalid("%s: license.spdx is required", id)
	}
	if len(k.Targets) == 0 {
		return invalid("%s: no targets", id)
	}
	for key, t := range k.Targets {
		if !reTarget.MatchString(key) {
			return invalid("%s: target key %q invalid", id, key)
		}
		if t == nil {
			continue
		}
		if err := t.validate(id+" "+key, k.Run); err != nil {
			return err
		}
	}
	// A kernel that is unavailable everywhere is legal, but then Run need not
	// be complete; otherwise it must be.
	if k.hasBuild() {
		if len(k.Run.VersionCmd) == 0 {
			return invalid("%s: run.version_cmd is required", id)
		}
		for _, a := range k.Run.VersionCmd {
			if a == "" {
				return invalid("%s: run.version_cmd has an empty argument", id)
			}
		}
		if k.Run.VersionRegex != "" {
			re, err := regexp.Compile(k.Run.VersionRegex)
			if err != nil || re.NumSubexp() != 1 || len(k.Run.VersionRegex) > 200 {
				return invalid("%s: run.version_regex must compile and have exactly one group", id)
			}
		}
	}
	for _, r := range k.Revoked {
		if r.Version == "" && r.SHA256 == "" {
			return invalid("%s: revoked entry needs version or sha256", id)
		}
		if r.SHA256 != "" && !reSHA256.MatchString(r.SHA256) {
			return invalid("%s: revoked sha256 invalid", id)
		}
	}
	return nil
}

func (k *Kernel) hasBuild() bool {
	for _, t := range k.Targets {
		if t != nil {
			return true
		}
	}
	return false
}

func (t *Target) validate(where string, run Run) error {
	if t.Archive != ArchiveTarGz && t.Archive != ArchiveZip {
		return invalid("%s: archive %q unsupported", where, t.Archive)
	}
	if !reSHA256.MatchString(t.ArchiveSHA256) {
		return invalid("%s: archive_sha256 must be 64 lowercase hex", where)
	}
	if t.ArchiveSize <= 0 || t.ArchiveSize > MaxArchiveBytes {
		return invalid("%s: archive_size out of range", where)
	}
	if len(t.URLs) == 0 || len(t.URLs) > MaxURLs {
		return invalid("%s: need 1..%d urls", where, MaxURLs)
	}
	for _, s := range t.URLs {
		u, err := url.Parse(s)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
			return invalid("%s: url %q invalid", where, s)
		}
	}
	if len(t.Extract) == 0 || len(t.Extract) > MaxExtractFiles {
		return invalid("%s: need 1..%d extract entries", where, MaxExtractFiles)
	}
	tos := map[string]bool{}
	froms := map[string]bool{}
	for _, e := range t.Extract {
		if err := e.validate(where); err != nil {
			return err
		}
		if tos[e.To] || froms[path.Clean(e.From)] {
			return invalid("%s: duplicate extract entry %q", where, e.To)
		}
		tos[e.To] = true
		froms[path.Clean(e.From)] = true
	}
	if run.Binary == "" || !tos[run.Binary] {
		return invalid("%s: run.binary %q is not an extract target", where, run.Binary)
	}
	if t.InstalledSize < 0 || t.InstalledSize > 4*MaxExtractBytes {
		return invalid("%s: installed_size out of range", where)
	}
	return nil
}

func (e Extract) validate(where string) error {
	if !SafeArchivePath(e.From) {
		return invalid("%s: extract.from %q unsafe", where, e.From)
	}
	if !reFile.MatchString(e.To) || reservedNames[e.To] {
		return invalid("%s: extract.to %q must be a plain file name", where, e.To)
	}
	if !reSHA256.MatchString(e.SHA256) {
		return invalid("%s: extract %q sha256 invalid", where, e.To)
	}
	if e.Size <= 0 || e.Size > MaxExtractBytes {
		return invalid("%s: extract %q size out of range", where, e.To)
	}
	if _, err := ParseMode(e.Mode); err != nil {
		return invalid("%s: extract %q: %v", where, e.To, err)
	}
	return nil
}

// SafeArchivePath reports whether p is a relative, traversal-free archive
// member name (a leading "./" is tolerated).
func SafeArchivePath(p string) bool {
	if p == "" || strings.ContainsAny(p, "\x00\\") || strings.HasPrefix(p, "/") {
		return false
	}
	p = strings.TrimPrefix(p, "./")
	if p == "" {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return false
		}
	}
	return true
}

// ParseMode parses an octal permission string. Only the lower nine bits are
// allowed (no setuid/setgid/sticky) and the owner must be able to read.
func ParseMode(s string) (uint32, error) {
	v, err := strconv.ParseUint(s, 8, 32)
	if err != nil || s == "" {
		return 0, fmt.Errorf("mode %q is not an octal string", s)
	}
	if v&^0o777 != 0 {
		return 0, fmt.Errorf("mode %q has bits beyond rwxrwxrwx", s)
	}
	if v&0o400 == 0 {
		return 0, fmt.Errorf("mode %q is not owner-readable", s)
	}
	return uint32(v), nil
}

// TargetState distinguishes the three answers Lookup can give.
type TargetState int

const (
	// TargetAbsent: the kernel entry has no such key at all.
	TargetAbsent TargetState = iota
	// TargetNull: explicitly "no build for this platform".
	TargetNull
	// TargetPresent: a build exists.
	TargetPresent
)

// Lookup returns the target for a platform key and says whether it is
// present, explicitly null, or absent.
func (k *Kernel) Lookup(key string) (*Target, TargetState) {
	t, ok := k.Targets[key]
	switch {
	case !ok:
		return nil, TargetAbsent
	case t == nil:
		return nil, TargetNull
	}
	return t, TargetPresent
}

// Find returns the entry for name+version (version is normalised). A missing
// entry is kernel.ErrUnknownKernel.
func (m *Manifest) Find(name, version string) (*Kernel, error) {
	version = NormalizeVersion(version)
	for i := range m.Kernels {
		k := &m.Kernels[i]
		if k.Name == name && k.Version == version {
			return k, nil
		}
	}
	return nil, kernel.Newf(kernel.ErrUnknownKernel, name, version, "not listed in manifest sequence %d", m.Sequence)
}

// Versions lists the versions the manifest has for a kernel name.
func (m *Manifest) Versions(name string) []string {
	var out []string
	for i := range m.Kernels {
		if m.Kernels[i].Name == name {
			out = append(out, m.Kernels[i].Version)
		}
	}
	return out
}

// RevokedReason reports whether the version (of any entry of the same
// kernel name) or any given sha256 is revoked, and why.
func (m *Manifest) RevokedReason(name, version string, hashes ...string) (string, bool) {
	version = NormalizeVersion(version)
	for i := range m.Kernels {
		k := &m.Kernels[i]
		for _, r := range k.Revoked {
			if r.Version != "" && k.Name == name && NormalizeVersion(r.Version) == version {
				return reasonOr(r.Reason, "version revoked"), true
			}
			if r.SHA256 != "" {
				for _, h := range hashes {
					if h == r.SHA256 {
						return reasonOr(r.Reason, "hash "+h[:12]+" revoked"), true
					}
				}
			}
		}
	}
	return "", false
}

func reasonOr(r, def string) string {
	if r != "" {
		return r
	}
	return def
}

// Hashes returns archive and extracted-file hashes of a target, for
// revocation checks.
func (t *Target) Hashes() []string {
	h := []string{t.ArchiveSHA256}
	for _, e := range t.Extract {
		h = append(h, e.SHA256)
	}
	return h
}

// CheckAgent returns kernel.ErrAgentTooOld when agentVersion is older than
// the entry's min_agent. An empty agentVersion or "dev" disables the check
// (development builds).
func (k *Kernel) CheckAgent(agentVersion string) error {
	if k.MinAgent == "" || agentVersion == "" || agentVersion == "dev" {
		return nil
	}
	if CompareVersions(agentVersion, k.MinAgent) < 0 {
		return kernel.Newf(kernel.ErrAgentTooOld, k.Name, k.Version, "needs agent >= %s, running %s", k.MinAgent, agentVersion)
	}
	return nil
}

// CompareVersions compares dotted versions numerically ("1.10.0" > "1.9.9");
// a pre-release suffix ("1.0.0-rc1") sorts before the release. Non-numeric
// fields compare as strings. It returns -1, 0 or 1.
func CompareVersions(a, b string) int {
	a, b = NormalizeVersion(a), NormalizeVersion(b)
	ac, ap := splitPre(a)
	bc, bp := splitPre(b)
	as, bs := strings.Split(ac, "."), strings.Split(bc, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		var x, y string
		if i < len(as) {
			x = as[i]
		}
		if i < len(bs) {
			y = bs[i]
		}
		if c := cmpField(x, y); c != 0 {
			return c
		}
	}
	switch {
	case ap == "" && bp != "":
		return 1
	case ap != "" && bp == "":
		return -1
	}
	return cmpField(ap, bp)
}

func splitPre(v string) (core, pre string) {
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		return v[:i], v[i+1:]
	}
	return v, ""
}

func cmpField(x, y string) int {
	xn, xe := strconv.ParseUint(x, 10, 64)
	yn, ye := strconv.ParseUint(y, 10, 64)
	if x == "" {
		xn, xe = 0, nil
	}
	if y == "" {
		yn, ye = 0, nil
	}
	if xe == nil && ye == nil {
		switch {
		case xn < yn:
			return -1
		case xn > yn:
			return 1
		}
		return 0
	}
	return strings.Compare(x, y)
}
