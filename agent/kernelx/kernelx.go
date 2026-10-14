// Package kernelx adapts kernel/install's Installer and kernel/manifest's
// signed manifest to agent/reconcile's KernelEnsurer interface. It is the
// production kernel manager of the agent: the reconciler never imports the
// kernel packages, it only sees this adapter.
//
// Trust: the embedded manifest keys are the production trust root (injected at
// release time through manifest.ExtraKeys or the embedded key list). For local
// and self-hosted deployments an operator may list additional ed25519 public
// keys in a file (Options.KeysPath, hex, one per line); they are added to the
// embedded set, never replacing it. A build with no embedded key and no extra
// key file rejects every manifest (kernel.ErrNoTrustedKeys), which is the
// intended fail-closed default.
package kernelx

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/selinux"
	"github.com/W1nCwC/W1nCray/agent/spec"
	"github.com/W1nCwC/W1nCray/kernel/install"
	"github.com/W1nCwC/W1nCray/kernel/manifest"
)

// Options configures an Ensurer.
type Options struct {
	// Dir is the kernel base directory; kernels live under <Dir>/kernels.
	// Required.
	Dir string
	// ManifestPath is a signed manifest file to load at start-up. Empty means
	// no manifest is loaded: only the builtin xray engine can run, and every
	// external engine reports unavailable.
	ManifestPath string
	// KeysPath is an optional file with extra trusted ed25519 public keys
	// (hex, one per line, '#' comments allowed). It is added to the embedded
	// production keys; production builds should inject keys with ldflags
	// (-X .../kernel/manifest.ExtraKeys=...) instead.
	KeysPath string
	// AgentVersion is compared with a kernel's min_agent ("" or "dev" skips).
	AgentVersion string
	// AllowHTTP permits http:// kernel sources (development/self-hosted only;
	// content hashes still apply). Never enable in production.
	AllowHTTP bool
	// PIDDir is the supervisor's pid directory (<StateDir>/pid). It is what
	// lets RunningVersion tell which version is really executing. Empty
	// disables the check: "in use" then falls back to the current pointer.
	PIDDir string
	// Labeler applies the bin_t label to the kernel tree on an SELinux
	// machine. Nil disables labelling.
	Labeler *selinux.Labeler
	// Log receives installer events.
	Log driver.Logger
}

// Ensurer implements reconcile.KernelEnsurer on top of an install.Installer.
type Ensurer struct {
	in *install.Installer
	// pidDir and kernelsRoot resolve "which version is running" (inuse.go).
	pidDir      string
	kernelsRoot string
	labeler     *selinux.Labeler
	log         driver.Logger
}

var _ interface {
	Ensure(ctx context.Context, pin spec.KernelPin) (driver.Installed, error)
	Available(name string) (bool, string)
} = (*Ensurer)(nil)

// New builds an Ensurer. The kernel directory is created if needed and, when
// ManifestPath is set, the signed manifest is verified and loaded.
func New(o Options) (*Ensurer, error) {
	if o.Dir == "" {
		return nil, fmt.Errorf("kernelx: Dir is required")
	}
	keys, err := loadKeys(o.KeysPath)
	if err != nil {
		return nil, err
	}
	in, err := install.New(install.Config{
		Dir:          o.Dir,
		Keys:         keys,
		AgentVersion: o.AgentVersion,
		AllowHTTP:    o.AllowHTTP,
		Log:          o.Log,
	})
	if err != nil {
		return nil, fmt.Errorf("kernelx: %w", err)
	}
	root, err := filepath.Abs(o.Dir)
	if err != nil {
		return nil, fmt.Errorf("kernelx: %w", err)
	}
	e := &Ensurer{
		in:     in,
		pidDir: o.PIDDir,
		// install.New keeps its kernels under <Dir>/kernels (install.go:131).
		kernelsRoot: filepath.Join(root, "kernels"),
		labeler:     o.Labeler,
		log:         o.Log,
	}
	if o.ManifestPath != "" {
		raw, err := os.ReadFile(o.ManifestPath)
		if err != nil {
			return nil, fmt.Errorf("kernelx: read manifest %s: %w", o.ManifestPath, err)
		}
		if err := in.LoadManifest(raw); err != nil {
			return nil, fmt.Errorf("kernelx: load manifest %s: %w", o.ManifestPath, err)
		}
	}
	return e, nil
}

// loadKeys combines the keys compiled into this build with the extra key file.
// It returns nil when neither source yields a key, so the installer applies its
// own (failing) default and manifests stay rejected.
func loadKeys(path string) ([]manifest.Key, error) {
	var keys []manifest.Key
	if embedded, err := manifest.DefaultKeys(); err == nil {
		keys = embedded
	}
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("kernelx: read manifest keys %s: %w", path, err)
		}
		extra, err := manifest.ParseKeys(string(b))
		if err != nil {
			return nil, fmt.Errorf("kernelx: manifest keys %s: %w", path, err)
		}
		keys = append(keys, extra...)
	}
	if len(keys) == 0 {
		return nil, nil
	}
	return keys, nil
}

// LoadManifest verifies raw against the trusted keys and, only when it is
// authentic (signature, expiry, sequence >= the highest sequence ever
// accepted), makes it the manifest in force and persists it. On any error the
// previously accepted manifest stays in force and nothing is written.
//
// It is safe for concurrent use: install.Installer serialises every public
// method (including LoadManifest and Manifest) with its own mutex, so the
// Ensurer needs no second lock. A manifest that fails verification is never
// written to disk and never reaches the running instances.
func (e *Ensurer) LoadManifest(raw []byte) error {
	return e.in.LoadManifest(raw)
}

// ManifestSequence returns the sequence of the manifest currently in force and
// reports whether one is loaded. It is for logging and status only; the
// sequence is the strictly monotonic counter the installer enforces against
// rollbacks.
func (e *Ensurer) ManifestSequence() (int64, bool) {
	m := e.in.Manifest()
	if m == nil {
		return 0, false
	}
	return m.Sequence, true
}

// Ensure makes the pinned kernel installed and current. An empty pin.Version
// selects the highest version the manifest lists as available on this machine.
//
// After a successful install it also applies the SELinux bin_t label to the
// kernel tree. That step is best effort here (a machine with SELinux off, or
// without the labelling tools, is a no-op) because the service manager labels
// again — and fails loudly — right before it starts a kernel.
func (e *Ensurer) Ensure(ctx context.Context, pin spec.KernelPin) (driver.Installed, error) {
	inst, err := e.ensure(ctx, pin, false)
	if err != nil {
		return inst, err
	}
	e.labelBestEffort(ctx)
	return inst, nil
}

// EnsureForce is Ensure for an operator-initiated install (the panel's
// kernel_install): it bypasses and clears the automatic retry back-off, so a
// version an operator explicitly asks for after a rollback is really attempted
// (D-M3). The reconcile loop keeps using Ensure and its back-off.
func (e *Ensurer) EnsureForce(ctx context.Context, pin spec.KernelPin) (driver.Installed, error) {
	inst, err := e.ensure(ctx, pin, true)
	if err != nil {
		return inst, err
	}
	e.labelBestEffort(ctx)
	return inst, nil
}

// ensure is Ensure/EnsureForce without the labelling step.
func (e *Ensurer) ensure(ctx context.Context, pin spec.KernelPin, force bool) (driver.Installed, error) {
	if pin.Version == "" {
		v, err := e.defaultVersion(pin.Name)
		if err != nil {
			return driver.Installed{}, err
		}
		pin.Version = v
	}
	if force {
		return e.in.EnsureForce(ctx, pin)
	}
	return e.in.Ensure(ctx, pin)
}

// LabelKernels makes every installed kernel binary of this machine bin_t, so
// an init system with SELinux enforcing starts them in unconfined_service_t
// instead of init_t (agent/selinux). It is what xraysvc calls before it starts
// the Xray service, and it is idempotent.
func (e *Ensurer) LabelKernels(ctx context.Context) error {
	if e == nil || e.labeler == nil {
		return nil
	}
	return e.labeler.EnsureBinT(ctx, e.kernelsRoot)
}

// labelBestEffort labels the kernel tree and only logs a failure: the install
// itself succeeded, and the caller that starts a kernel reports the real
// problem with a much better message.
func (e *Ensurer) labelBestEffort(ctx context.Context) {
	if err := e.LabelKernels(ctx); err != nil && e.log != nil {
		e.log.Warnf("kernel: SELinux 标签设置失败: %v", err)
	}
}

// defaultVersion is the newest available version of a kernel in the manifest.
func (e *Ensurer) defaultVersion(name string) (string, error) {
	m := e.in.Manifest()
	if m == nil {
		return "", fmt.Errorf("kernelx: no signed manifest loaded; cannot pick a default version for %q", name)
	}
	best := ""
	for _, v := range m.Versions(name) {
		if best == "" || manifest.CompareVersions(v, best) > 0 {
			best = v
		}
	}
	if best == "" {
		return "", fmt.Errorf("kernelx: manifest lists no version of kernel %q", name)
	}
	return best, nil
}

// Available reports whether the kernel can be used on this machine: a manifest
// must be loaded and list at least one version of name that is installable here
// (target present and compatible, not revoked, agent new enough).
func (e *Ensurer) Available(name string) (bool, string) {
	if e.in.Manifest() == nil {
		return false, "no signed kernel manifest loaded (set Agent.ManifestPath)"
	}
	cat, err := e.in.Catalog()
	if err != nil {
		return false, err.Error()
	}
	found, reason := false, ""
	for _, ce := range cat {
		if ce.Name != name {
			continue
		}
		found = true
		if ce.Available {
			return true, ""
		}
		if reason == "" {
			reason = ce.Reason
		}
	}
	if !found {
		return false, fmt.Sprintf("kernel %q is not listed in the manifest", name)
	}
	return false, reason
}

// Installed reports whether some version of the kernel is already installed.
// The reconciler uses it to skip the free-space check for an installed kernel.
func (e *Ensurer) Installed(name string) bool {
	_, err := e.in.Current(name)
	return err == nil
}
