package kernel

import (
	"errors"
	"fmt"
)

// Sentinel error kinds. Every error returned by the kernel packages wraps
// exactly one of these (use errors.Is) and, where it concerns a concrete
// kernel, is an *Error carrying the kernel name, version and target.
//
// Reconciler guidance: ErrUnavailable, ErrNoSpace, ErrAgentTooOld, ErrRevoked,
// ErrUnknownKernel are "this machine cannot run this pin" results the panel
// should show greyed out; ErrBackoff, ErrDownload, ErrClock are transient;
// ErrSignature, ErrStaleManifest, ErrExpired, ErrVerify, ErrCheck are
// integrity failures that must be reported prominently and never bypassed.
var (
	// ErrNoManifest: no signed manifest has been loaded yet.
	ErrNoManifest = errors.New("no kernel manifest loaded")
	// ErrNoTrustedKeys: the agent binary carries no manifest public keys.
	ErrNoTrustedKeys = errors.New("no trusted manifest keys")
	// ErrSignature: signature missing, malformed, from an unknown key, or wrong.
	ErrSignature = errors.New("manifest signature invalid")
	// ErrManifestInvalid: the (correctly signed or not) manifest is malformed.
	ErrManifestInvalid = errors.New("manifest invalid")
	// ErrExpired: manifest expires_at has passed (freeze-attack protection).
	ErrExpired = errors.New("manifest expired")
	// ErrStaleManifest: manifest sequence is lower than one already accepted
	// (rollback protection).
	ErrStaleManifest = errors.New("manifest sequence older than accepted")
	// ErrClock: the local clock is earlier than the manifest issue time, so
	// expiry cannot be judged (typical for routers before NTP sync).
	ErrClock = errors.New("system clock earlier than manifest issue time")

	// ErrUnknownKernel: the manifest has no such kernel name/version. This is
	// distinct from ErrUnavailable, which means the manifest knows the kernel
	// but has no usable build for this machine.
	ErrUnknownKernel = errors.New("kernel/version not in manifest")
	// ErrUnavailable: the manifest declares no build for this platform (the
	// target is null/absent, or incompatible with this CPU/libc).
	ErrUnavailable = errors.New("kernel not available for this platform")
	// ErrAgentTooOld: the kernel requires a newer agent (min_agent).
	ErrAgentTooOld = errors.New("agent older than kernel min_agent")
	// ErrRevoked: the kernel version or one of its hashes is revoked.
	ErrRevoked = errors.New("kernel revoked")

	// ErrNoSpace: not enough free disk space; nothing was deleted.
	ErrNoSpace = errors.New("not enough free disk space")
	// ErrDownload: every download source failed (no integrity failure seen).
	ErrDownload = errors.New("download failed")
	// ErrVerify: a hash, size or archive-structure check failed. Fail-closed:
	// there is no way to skip it.
	ErrVerify = errors.New("verification failed")
	// ErrCheck: the installed binary did not report the expected version.
	ErrCheck = errors.New("version self-check failed")
	// ErrBackoff: this version failed recently and is in retry back-off.
	ErrBackoff = errors.New("version in retry back-off")

	// ErrNotInstalled: no such installed kernel/version.
	ErrNotInstalled = errors.New("kernel not installed")
	// ErrInUse: refused because it is the current version.
	ErrInUse = errors.New("kernel version is current")
)

// Error is the concrete error type of the kernel packages.
type Error struct {
	Kind    error  // one of the sentinels above
	Kernel  string // kernel name, may be empty
	Version string
	Target  string // manifest target key, may be empty
	Msg     string
	Err     error // underlying cause, may be nil
}

// Newf builds an *Error of the given kind.
func Newf(kind error, kernel, version, format string, args ...any) *Error {
	return &Error{Kind: kind, Kernel: kernel, Version: version, Msg: fmt.Sprintf(format, args...)}
}

// Wrap is Newf with an underlying cause.
func Wrap(kind error, kernel, version string, cause error, format string, args ...any) *Error {
	e := Newf(kind, kernel, version, format, args...)
	e.Err = cause
	return e
}

func (e *Error) Error() string {
	s := e.Kind.Error()
	if e.Kernel != "" {
		s = e.Kernel
		if e.Version != "" {
			s += "@" + e.Version
		}
		if e.Target != "" {
			s += " [" + e.Target + "]"
		}
		s += ": " + e.Kind.Error()
	}
	if e.Msg != "" {
		s += ": " + e.Msg
	}
	if e.Err != nil {
		s += ": " + e.Err.Error()
	}
	return s
}

// Unwrap lets errors.Is/As see both the kind and the cause.
func (e *Error) Unwrap() []error {
	if e.Err == nil {
		return []error{e.Kind}
	}
	return []error{e.Kind, e.Err}
}

// Code returns a short stable machine-readable reason for err, suitable for
// reporting to the panel. Unknown errors map to "error".
func Code(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrNoManifest):
		return "no_manifest"
	case errors.Is(err, ErrNoTrustedKeys):
		return "no_trusted_keys"
	case errors.Is(err, ErrSignature):
		return "bad_signature"
	case errors.Is(err, ErrManifestInvalid):
		return "manifest_invalid"
	case errors.Is(err, ErrExpired):
		return "manifest_expired"
	case errors.Is(err, ErrStaleManifest):
		return "manifest_stale"
	case errors.Is(err, ErrClock):
		return "clock_invalid"
	case errors.Is(err, ErrUnknownKernel):
		return "unknown_kernel"
	case errors.Is(err, ErrUnavailable):
		return "unavailable"
	case errors.Is(err, ErrAgentTooOld):
		return "agent_too_old"
	case errors.Is(err, ErrRevoked):
		return "revoked"
	case errors.Is(err, ErrNoSpace):
		return "no_space"
	case errors.Is(err, ErrVerify):
		return "verify_failed"
	case errors.Is(err, ErrCheck):
		return "check_failed"
	case errors.Is(err, ErrBackoff):
		return "backoff"
	case errors.Is(err, ErrDownload):
		return "download_failed"
	case errors.Is(err, ErrNotInstalled):
		return "not_installed"
	case errors.Is(err, ErrInUse):
		return "in_use"
	}
	return "error"
}
