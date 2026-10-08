// Package agentcfg owns the agent's own configuration: the agent.yml file and
// the "Agent:" block of config.yml (PLAN v9 D1). The types live here so that
// link, check, install.sh and the agent core read one definition, and so the
// panel can alias them without an import cycle (design R1 / ruling 1).
package agentcfg

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/spf13/viper"

	"github.com/W1nCwC/W1nCray/agent/panelclient"
	"github.com/W1nCwC/W1nCray/agent/selfupdate"
	"github.com/W1nCwC/W1nCray/agent/spec"
	"github.com/W1nCwC/W1nCray/nodecfg"
)

// FileName is the conventional name looked for next to config.yml.
const FileName = "agent.yml"

// The agent's state files under StateDir. The names are duplicated from
// agent/state (unexported there) because the managed-file exclusion list has to
// name them without importing that package.
const (
	StateFileDesired  = "desired.json"
	StateFileLastGood = "last_good.json"
)

// Config configures the in-process agent: a declarative kernel manager that
// applies a desired state (from DesiredPath) to the configured engines. It is
// independent of the Xboard Nodes; either may be configured. It is the root of
// agent.yml and the shape of the config.yml "Agent:" block, so both files use
// exactly the same field names (ruling 1).
type Config struct {
	Enabled bool `mapstructure:"Enabled"`
	// StateDir holds the agent's state files and per-driver directories.
	// Default: a "state" directory next to the config file.
	StateDir string `mapstructure:"StateDir"`
	// ManifestPath is the signed kernel manifest. Empty: only the builtin xray
	// engine is available (no external kernel can be installed).
	ManifestPath string `mapstructure:"ManifestPath"`
	// ManifestKeysPath is an optional file of extra trusted ed25519 public
	// keys (hex, one per line), added to the keys compiled into the binary.
	// For local/self-hosted use; production should inject keys with ldflags.
	ManifestKeysPath string `mapstructure:"ManifestKeysPath"`
	// KernelsDir is where external kernels are installed.
	// Default: StateDir/kernels.
	KernelsDir string `mapstructure:"KernelsDir"`
	// DesiredPath is a JSON file holding a spec.Desired. When set, the agent
	// applies it at start-up and re-applies it (debounced) on every change.
	DesiredPath string `mapstructure:"DesiredPath"`
	// Policy is the local root-of-trust policy; remote desired state can never
	// relax it.
	Policy *Policy `mapstructure:"Policy"`
	// Panel links the agent to a panel (W1nCBoard/Xboard) that pushes the
	// desired state and receives the status reports. It requires the agent to
	// be enabled and never relaxes Policy.
	Panel *PanelConfig `mapstructure:"Panel"`
	// Terminal is the local switch of the interactive terminal (D8). It is ON by
	// default (the owner's decision); a machine opts out locally with
	// `Terminal: {Enabled: false}` or the installer/link flag --noterminal.
	Terminal *TerminalConfig `mapstructure:"Terminal"`
	// Files is the local file-operation policy (D9).
	Files *FilesConfig `mapstructure:"Files"`
	// Modules is the local module switch (D3).
	Modules *ModuleConfig `mapstructure:"Modules"`
	// Firewall is the local firewall-automation switch (PLAN v11 D2). On
	// OpenWrt the agent opens the WAN ports of the instances it runs; anywhere
	// else it never touches the firewall.
	Firewall *FirewallConfig `mapstructure:"Firewall"`
	// Kernels is the local kernel-source switch (D-M1): it permits plain
	// http:// mirrors for the signed manifest's assets. It is off by default
	// and only a local file can turn it on.
	Kernels *KernelsConfig `mapstructure:"Kernels"`
	// Drivers holds the local driver timing overrides (D4).
	Drivers *DriversConfig `mapstructure:"Drivers"`
	// SelfUpdate holds the local self-update watchdog timing (D-M7). It is a
	// local-only override: the panel never pushes agent configuration.
	SelfUpdate *SelfUpdateConfig `mapstructure:"SelfUpdate"`

	// dir is the directory the relative paths were resolved against and
	// excludedFiles are the paths that are never reachable through
	// Files.Roots (ruling 9/13). ResolveLocalPolicy fills both; they are not
	// part of the file format.
	dir           string
	excludedFiles []string
	// source records which file the effective configuration came from
	// (agent.yml or the config.yml "Agent:" block). panel.LoadConfig sets it
	// through SetSource; the zero value means "not resolved".
	source Source
}

// SetSource records which file the effective agent configuration came from. It
// is called by the loader (panel.LoadConfig) right after Resolve, so the
// managed-file layer can tell the separated layout from the single-file one
// without re-reading the directory (ruling 2).
func (c *Config) SetSource(s Source) {
	if c != nil {
		c.source = s
	}
}

// PanelConfig configures the agent <-> panel link (the wire contract is
// docs/WS-PROTOCOL.md). The agent connects out to the panel; the panel never
// connects to the agent.
type PanelConfig struct {
	Enabled bool `mapstructure:"Enabled"`
	// URL is the panel origin, for example https://panel.example.com. It must
	// be https unless it is a loopback host or AllowInsecureHTTP is set.
	URL string `mapstructure:"URL"`
	// MachineID is the machine id on the panel.
	MachineID int `mapstructure:"MachineID"`
	// Token is the machine token. Exactly one of Token and TokenFile must be
	// set; TokenFile keeps the secret out of the config file.
	Token string `mapstructure:"Token"`
	// TokenFile holds the machine token (surrounding whitespace is ignored).
	// On Unix-like systems the file must not be readable by group or other.
	// A relative path is resolved against the config file's directory.
	TokenFile string `mapstructure:"TokenFile"`
	// PullIntervalSec and ReportIntervalSec default to 30 and are clamped to
	// [10, 300] seconds.
	PullIntervalSec   int `mapstructure:"PullIntervalSec"`
	ReportIntervalSec int `mapstructure:"ReportIntervalSec"`
	// ManifestSync enables the signed kernel manifest sync: the agent fetches
	// GET /manifest from the panel and its local Ensurer verifies the
	// signature before the manifest is used. Nil means the default (enabled
	// whenever Panel.Enabled); set it to false to keep the panel from
	// supplying the kernel manifest.
	ManifestSync *bool `mapstructure:"ManifestSync"`
	// ManifestIntervalSec is how often the manifest is re-fetched. Default
	// 3600; clamped to [300, 86400] seconds.
	ManifestIntervalSec int `mapstructure:"ManifestIntervalSec"`
	// AllowInsecureHTTP permits plain http:// to a non-loopback host
	// (development only).
	AllowInsecureHTTP bool `mapstructure:"AllowInsecureHTTP"`
	// MachineNodes makes the panel decide which nodes this machine runs
	// (instead of the per-node Nodes entries): W1nCray asks the panel for the
	// machine's node list and starts one controller per node. It requires
	// Panel.Enabled (and the agent).
	MachineNodes bool `mapstructure:"MachineNodes"`
	// NodeController is the ControllerConfig template shared by every machine
	// node (ListenIP, CertConfig, ...). Missing fields fall back to the node
	// defaults.
	NodeController *nodecfg.Config `mapstructure:"NodeController"`
	// NodeControllers overrides NodeController for individual machine nodes,
	// keyed by the panel's node id (the same field layout as
	// Nodes[].ControllerConfig). An entry that exists is used as a whole: it is
	// never merged field by field with NodeController, so a node cannot inherit
	// a setting by accident. It is still completed with the node defaults.
	// Typical use: a node that needs PROXY protocol, its own certificate or a
	// local DNS/REALITY setup, including credentials that must stay on this
	// machine and are never sent to the panel.
	NodeControllers map[int]*nodecfg.Config `mapstructure:"NodeControllers"`
}

// Policy maps agent/spec.Policy fields onto the config file. A zero value
// keeps the agent defaults (loopback-only listeners, ports >= 1024, ...).
type Policy struct {
	MaxInstances             int      `mapstructure:"MaxInstances"`
	MaxPortsPerInstance      int      `mapstructure:"MaxPortsPerInstance"`
	AllowListen              []string `mapstructure:"AllowListen"`
	PrivilegedPorts          bool     `mapstructure:"PrivilegedPorts"`
	PortRange                []int    `mapstructure:"PortRange"` // [lo, hi]
	DenyPorts                []int    `mapstructure:"DenyPorts"`
	DenyCIDRs                []string `mapstructure:"DenyCIDRs"`
	AllowPrivate             bool     `mapstructure:"AllowPrivate"`
	AllowAnyTarget           bool     `mapstructure:"AllowAnyTarget"`
	AllowAcceptProxyOnPublic bool     `mapstructure:"AllowAcceptProxyOnPublic"`
	AllowEngines             []string `mapstructure:"AllowEngines"`
}

// Terminal defaults (D8: at most two sessions per machine, idle 15 min, hard
// limit 4 h). The zero value of TerminalConfig means "disabled, use the
// defaults"; the accessors below materialise them.
const (
	DefaultTerminalSessions     = 2
	MaxTerminalSessions         = 2
	DefaultTerminalIdleSeconds  = 900
	DefaultTerminalMaxDurationS = 14400
)

// TerminalConfig is the local switch of the interactive terminal (D8). It is a
// local gate the panel can never relax (ruling 13). Only the types and their
// validation live here; the behaviour is implemented by agent/terminal.
type TerminalConfig struct {
	// Enabled is a pointer on purpose: nil (not written) means the default, ON.
	// Only an explicit false turns the terminal off, so writing just MaxSessions
	// cannot disable it by accident.
	Enabled *bool `mapstructure:"Enabled"`
	// MaxSessions is the number of concurrent sessions; 0 means the default.
	MaxSessions int `mapstructure:"MaxSessions"`
	// IdleTimeoutS closes an idle session; 0 means the default.
	IdleTimeoutS int `mapstructure:"IdleTimeoutS"`
	// MaxDurationS is the hard session lifetime; 0 means the default.
	MaxDurationS int `mapstructure:"MaxDurationS"`
}

// Sessions returns the concurrent-session limit, defaulted.
func (t *TerminalConfig) Sessions() int {
	if t == nil || t.MaxSessions == 0 {
		return DefaultTerminalSessions
	}
	return t.MaxSessions
}

// IdleTimeout returns how long a session may stay idle, defaulted.
func (t *TerminalConfig) IdleTimeout() time.Duration {
	if t == nil || t.IdleTimeoutS == 0 {
		return DefaultTerminalIdleSeconds * time.Second
	}
	return time.Duration(t.IdleTimeoutS) * time.Second
}

// MaxDuration returns the hard session lifetime, defaulted.
func (t *TerminalConfig) MaxDuration() time.Duration {
	if t == nil || t.MaxDurationS == 0 {
		return DefaultTerminalMaxDurationS * time.Second
	}
	return time.Duration(t.MaxDurationS) * time.Second
}

// Validate checks the terminal section. The values are refused instead of
// clamped: a local gate that silently ignores what the operator wrote is worse
// than one that refuses to start.
func (t *TerminalConfig) Validate() error {
	if t == nil {
		return nil
	}
	if t.MaxSessions < 0 || t.MaxSessions > MaxTerminalSessions {
		return fmt.Errorf("config: Agent.Terminal.MaxSessions must be 0 (default %d) or at most %d, got %d",
			DefaultTerminalSessions, MaxTerminalSessions, t.MaxSessions)
	}
	if t.IdleTimeoutS < 0 {
		return fmt.Errorf("config: Agent.Terminal.IdleTimeoutS must not be negative")
	}
	if t.MaxDurationS < 0 {
		return fmt.Errorf("config: Agent.Terminal.MaxDurationS must not be negative")
	}
	if t.IdleTimeoutS > 0 && t.MaxDurationS > 0 && t.IdleTimeoutS > t.MaxDurationS {
		return fmt.Errorf("config: Agent.Terminal.IdleTimeoutS (%d) must not exceed MaxDurationS (%d)",
			t.IdleTimeoutS, t.MaxDurationS)
	}
	return nil
}

// FilesConfig is the local file-operation policy (D9, ruling 13). Roots are
// resolved and defaulted by ResolveLocalPolicy (xray config directory + state
// directory) unless the machine is unrestricted; AllowExec defaults to false,
// so the zero value is the safe one. Only the types and their validation live
// here; the behaviour is implemented by agent/fileops.
type FilesConfig struct {
	Roots []string `mapstructure:"Roots"`
	// Unrestricted is a THREE-STATE switch (PLAN v10):
	//
	//   - not written (nil): follow the terminal gate. A machine whose root
	//     shell is already reachable gains nothing from confining the file
	//     manager — the terminal can do anything the file manager can, only
	//     less conveniently — so an effective terminal means "unrestricted".
	//   - explicit true: unrestricted, whatever the terminal says.
	//   - explicit false: the roots check always applies, even with the
	//     terminal on.
	//
	// ResolveLocalPolicy materialises the value (so the field is non-nil after
	// the load and every consumer sees the effective one); Config.
	// UnrestrictedEnabled reads it defensively. In unrestricted mode the panel
	// names an absolute path and sends an empty root.
	Unrestricted *bool `mapstructure:"Unrestricted"`
	AllowExec    bool  `mapstructure:"AllowExec"`
	// MaxBytes bounds one managed-file blob (managed files are downloaded by
	// sha256, see agent/filesync). 0 means the built-in default (64 MiB). A
	// negative value turns geo downloads off locally: a machine that keeps no
	// geoip.dat/geosite.dat (the OpenWrt installer default) refuses them with
	// "geo files disabled by local policy" instead of silently skipping them.
	MaxBytes int64 `mapstructure:"MaxBytes"`
	// MaxGeoBytes overrides MaxBytes for geoip.dat and geosite.dat. 0 means
	// MaxBytes.
	MaxGeoBytes int64 `mapstructure:"MaxGeoBytes"`
}

// ModuleConfig is the local module switch (D3, ruling 6). A nil XrayNodes means
// on; the panel can only ask for nodes, never relax this gate.
type ModuleConfig struct {
	XrayNodes *bool `mapstructure:"XrayNodes"`
}

// FirewallConfig is the local firewall-automation switch (PLAN v11 D2).
// AutoOpen is a pointer on purpose: nil (not written) follows the platform
// default, which is ON on OpenWrt and OFF everywhere else. Only OpenWrt is
// implemented in this release: on another system the agent never touches the
// firewall, whatever the field says.
type FirewallConfig struct {
	AutoOpen *bool `mapstructure:"AutoOpen"`
}

// KernelsConfig is the local kernel-source policy (D-M1). AllowHTTP permits
// plain http:// sources for the assets of the signed kernel manifest.
//
// It is a LOCAL switch on purpose: the panel pushes a desired state and never
// agent configuration, so it cannot turn this on remotely. Integrity does not
// depend on it — the manifest is signed and every asset is checked against the
// sha256 the manifest carries — which is exactly why an operator with a
// self-hosted, internal-only mirror (no TLS) may want it. The default is off:
// https only.
type KernelsConfig struct {
	AllowHTTP bool `mapstructure:"AllowHTTP"`
}

// KernelsAllowHTTP returns the effective Kernels.AllowHTTP value. The zero
// value is false (https only), so a missing section, a nil Config and a Config
// that was never resolved all keep the fail-closed default.
func (c *Config) KernelsAllowHTTP() bool {
	if c == nil || c.Kernels == nil {
		return false
	}
	return c.Kernels.AllowHTTP
}

// DriversConfig holds the local driver timing overrides (D4, F6). Every field
// is optional; a zero value means "use the driver's own default", which is
// per-architecture and per-OpenWrt where that matters
// (driver.DefaultReadyTimeout).
type DriversConfig struct {
	Frp  *FrpConfig  `mapstructure:"Frp"`
	Gost *GostConfig `mapstructure:"Gost"`
}

// FrpConfig overrides the frp driver's readiness limit (D4).
type FrpConfig struct {
	// ReadyTimeoutSec bounds how long the driver waits for a started frps/frpc
	// instance to answer before it reports that instance as failed. 0 means
	// the shared default (driver.DefaultReadyTimeout): 15s on amd64/arm64 off
	// OpenWrt, 60s on the slower targets and on every architecture running
	// OpenWrt. Raise it on a device that is slower than its architecture
	// suggests; the value is a local one, never pushed by the panel.
	ReadyTimeoutSec int `mapstructure:"ReadyTimeoutSec"`
}

// GostConfig overrides the gost driver's readiness limit (F6). It is
// symmetrical with FrpConfig: the same shared default and the same local-only
// override, because the T2 run measured gost's old hard-coded 10s limit timing
// out on MIPS just like frp's 15s one.
type GostConfig struct {
	// ReadyTimeoutSec bounds how long the driver waits for the gost process
	// and each of its services to answer before it reports the instance as
	// failed. 0 means the shared default (driver.DefaultReadyTimeout): 15s on
	// amd64/arm64 off OpenWrt, 60s on the slower targets and on every
	// architecture running OpenWrt. The value is a local one, never pushed by
	// the panel.
	ReadyTimeoutSec int `mapstructure:"ReadyTimeoutSec"`
}

// FrpReadyTimeout returns the configured frp readiness limit and whether it was
// set at all. A nil Config, a missing section and a non-positive value all mean
// "use the shared default" (driver.DefaultReadyTimeout).
func (c *Config) FrpReadyTimeout() (time.Duration, bool) {
	if c == nil || c.Drivers == nil || c.Drivers.Frp == nil || c.Drivers.Frp.ReadyTimeoutSec <= 0 {
		return 0, false
	}
	return time.Duration(c.Drivers.Frp.ReadyTimeoutSec) * time.Second, true
}

// GostReadyTimeout returns the configured gost readiness limit and whether it
// was set at all. A nil Config, a missing section and a non-positive value all
// mean "use the shared default" (driver.DefaultReadyTimeout). It is the gost
// mirror of FrpReadyTimeout (F6).
func (c *Config) GostReadyTimeout() (time.Duration, bool) {
	if c == nil || c.Drivers == nil || c.Drivers.Gost == nil || c.Drivers.Gost.ReadyTimeoutSec <= 0 {
		return 0, false
	}
	return time.Duration(c.Drivers.Gost.ReadyTimeoutSec) * time.Second, true
}

// SelfUpdateConfig overrides the self-update watchdog timing (D-M7). Every
// field is optional; 0 means "use the architecture default". The watchdog runs
// as a copy of the previous agent binary, so it always runs on this machine's
// architecture.
type SelfUpdateConfig struct {
	// AliveWindowSec is how long the watchdog tolerates "no agent alive" after
	// the update before it rolls back. The default is 60 s on amd64/arm64 and
	// 180 s on the slower targets. It has to cover the service manager's
	// respawn delay plus the new process's start-up: raise it on a device that
	// is slower than its architecture suggests.
	AliveWindowSec int `mapstructure:"AliveWindowSec"`
	// DeadlineSec is the watchdog's total observation budget. The default is
	// 3 min on amd64/arm64 and 8 min on the slower targets. It is kept above
	// AliveWindowSec.
	DeadlineSec int `mapstructure:"DeadlineSec"`
}

// SelfUpdateAliveWindow returns the configured no-live-agent window and whether
// it was set at all.
func (c *Config) SelfUpdateAliveWindow() (time.Duration, bool) {
	if c == nil || c.SelfUpdate == nil || c.SelfUpdate.AliveWindowSec <= 0 {
		return 0, false
	}
	return time.Duration(c.SelfUpdate.AliveWindowSec) * time.Second, true
}

// SelfUpdateDeadline returns the configured watchdog budget and whether it was
// set at all.
func (c *Config) SelfUpdateDeadline() (time.Duration, bool) {
	if c == nil || c.SelfUpdate == nil || c.SelfUpdate.DeadlineSec <= 0 {
		return 0, false
	}
	return time.Duration(c.SelfUpdate.DeadlineSec) * time.Second, true
}

// SelfUpdateWindows returns the effective (alive, deadline) pair for goarch:
// the local override when it was written, else the architecture default. A
// deadline that is not above the window is raised, so a misconfigured file
// cannot make the watchdog stop watching before its own rollback rule can fire.
func (c *Config) SelfUpdateWindows(goarch string) (alive, deadline time.Duration) {
	alive, deadline = selfupdate.DefaultWatchdogWindows(goarch)
	if v, ok := c.SelfUpdateAliveWindow(); ok {
		alive = v
	}
	if v, ok := c.SelfUpdateDeadline(); ok {
		deadline = v
	}
	if deadline <= alive {
		deadline = alive + 30*time.Second
	}
	return alive, deadline
}

// FirewallAutoOpen returns the effective value of Firewall.AutoOpen for a
// machine whose OpenWrt detection is openWrt. An explicit true/false written in
// the configuration is honoured on OpenWrt; "not written" is the platform
// default. A non-OpenWrt machine always answers false because the agent has no
// firewall automation there (the panel sees it in hello.policy.firewall).
func (c *Config) FirewallAutoOpen(openWrt bool) bool {
	if !openWrt {
		return false
	}
	if c == nil || c.Firewall == nil || c.Firewall.AutoOpen == nil {
		return true
	}
	return *c.Firewall.AutoOpen
}

// Load reads an agent.yml. A missing file returns (nil, nil): the caller then
// falls back to the config.yml "Agent:" block. A file that exists but cannot be
// read or parsed is an error: its presence is what makes it win, so a broken
// one must never silently fall back (design R5).
func Load(path string) (*Config, error) {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("agent config %s: %w", path, err)
	}
	v := viper.New()
	v.SetConfigFile(path)
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yml", ".yaml", ".json", ".toml":
	default:
		v.SetConfigType("yaml")
	}
	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("read agent config %s: %w", path, err)
	}
	cfg := new(Config)
	if err := v.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("parse agent config %s: %w", path, err)
	}
	return cfg, nil
}

// Validate checks the agent section. It is deliberately shallow: the policy is
// parsed in full by the agent core when a desired state is applied.
func (c *Config) Validate() error {
	if c == nil {
		return nil
	}
	// A local timing override is validated even when the agent is disabled: a
	// value that silently does nothing is worse than a clear refusal. Both
	// drivers share one rule (frp D4, gost F6).
	if c.Drivers != nil {
		if c.Drivers.Frp != nil && c.Drivers.Frp.ReadyTimeoutSec < 0 {
			return fmt.Errorf("config: Agent.Drivers.Frp.ReadyTimeoutSec must not be negative")
		}
		if c.Drivers.Gost != nil && c.Drivers.Gost.ReadyTimeoutSec < 0 {
			return fmt.Errorf("config: Agent.Drivers.Gost.ReadyTimeoutSec must not be negative")
		}
	}
	if c.SelfUpdate != nil && (c.SelfUpdate.AliveWindowSec < 0 || c.SelfUpdate.DeadlineSec < 0) {
		return fmt.Errorf("config: Agent.SelfUpdate.AliveWindowSec and DeadlineSec must not be negative")
	}
	if !c.Enabled {
		if c.Panel != nil && (c.Panel.Enabled || c.Panel.MachineNodes) {
			return fmt.Errorf("config: Agent.Panel.Enabled requires Agent.Enabled")
		}
		return nil
	}
	if c.Panel != nil {
		if err := c.Panel.Validate(); err != nil {
			return err
		}
	}
	if c.Policy != nil {
		if n := len(c.Policy.PortRange); n != 0 && n != 2 {
			return fmt.Errorf("config: Agent.Policy.PortRange must have two elements [lo, hi], got %d", n)
		}
		for _, e := range c.Policy.AllowEngines {
			switch e {
			case spec.EngineAuto, spec.EngineXray, spec.EngineGost, spec.EngineFrp, spec.EngineRealm:
			default:
				return fmt.Errorf("config: Agent.Policy.AllowEngines: unknown engine %q", e)
			}
		}
	}
	return c.Terminal.Validate()
}

// TerminalEnabled reports whether the interactive terminal is switched on
// locally. The default is on (D8) and the panel can never relax it.
func (c *Config) TerminalEnabled() bool {
	if c == nil {
		return false
	}
	return c.Terminal == nil || c.Terminal.Enabled == nil || *c.Terminal.Enabled
}

// UnrestrictedEnabled reports the effective Files.Unrestricted value: an
// explicit true/false is honoured as written, an absent value follows the
// terminal gate (see FilesConfig.Unrestricted). ResolveLocalPolicy materialises
// the field, so this accessor only has to cover a Config that was never
// resolved (a zero value, a test) — there the safe answer is "restricted".
func (c *Config) UnrestrictedEnabled() bool {
	if c == nil || c.Files == nil {
		return false
	}
	if c.Files.Unrestricted != nil {
		return *c.Files.Unrestricted
	}
	return c.TerminalEnabled()
}

// XrayNodesEnabled reports whether the local module gate allows node
// controllers (D3, ruling 6). The default is on.
func (c *Config) XrayNodesEnabled() bool {
	if c == nil || c.Modules == nil || c.Modules.XrayNodes == nil {
		return true
	}
	return *c.Modules.XrayNodes
}

// Dir is the directory the relative paths were resolved against: the directory
// of the file that won (agent.yml or config.yml).
func (c *Config) Dir() string {
	if c == nil {
		return ""
	}
	return c.dir
}

// SeparatedLayout reports whether this machine uses the agent.yml separation
// (D1): the agent's own configuration lives in agent.yml, so config.yml only
// carries the xray settings and may be managed by the panel (ruling 2). When
// the agent configuration comes from the config.yml "Agent:" block, that file
// is the agent's own configuration and must never be overwritten remotely.
func (c *Config) SeparatedLayout() bool {
	return c != nil && c.source == SourceAgentYML
}

// Separated reports whether an agent.yml exists next to configPath, which is
// what makes config.yml a managed file (ruling 2). It is a plain existence
// check: the caller may run before LoadConfig.
func Separated(configPath string) bool {
	if configPath == "" {
		return false
	}
	_, err := os.Stat(filepath.Join(filepath.Dir(configPath), FileName))
	return err == nil
}

// ExcludedFiles returns the absolute paths the managed-file layer must never
// read or write, even when they sit inside a configured root (ruling 9/13):
// agent.yml, desired.json and last_good.json.
func (c *Config) ExcludedFiles() []string {
	if c == nil {
		return nil
	}
	return append([]string(nil), c.excludedFiles...)
}

// ExcludedPaths returns the files that must never be reachable through
// Files.Roots: agent.yml next to configPath and the agent's state files under
// stateDir (ruling 9/13). An empty stateDir drops the state files.
func ExcludedPaths(configPath, stateDir string) []string {
	out := []string{filepath.Join(filepath.Dir(configPath), FileName)}
	if stateDir != "" {
		out = append(out, filepath.Join(stateDir, StateFileDesired), filepath.Join(stateDir, StateFileLastGood))
	}
	return out
}

// ResolveLocalPolicy materialises the local policy defaults (D3/D8/D9) and
// resolves their paths. base is the directory of the file that won, xrayDir is
// where config.yml lives (the xray managed-file root) and excluded lists the
// files that must never be inside a root (see ExcludedPaths).
//
// It is called after validation and after StateDir is resolved, so it never
// hides a config error.
func (c *Config) ResolveLocalPolicy(base, xrayDir string, excluded []string) error {
	if c == nil {
		return nil
	}
	if c.Files == nil {
		c.Files = &FilesConfig{}
	}
	// The three-state switch is resolved first: materialising it here is what
	// lets every consumer — the panel's fileops.Options, hello.policy.files —
	// read the effective value instead of the raw one. An absent value follows
	// the terminal gate (see FilesConfig.Unrestricted).
	if c.Files.Unrestricted == nil {
		v := c.TerminalEnabled()
		c.Files.Unrestricted = &v
	}
	if len(c.Files.Roots) == 0 {
		// Default: the xray configuration directory and the agent state
		// directory, nothing else (D9). The default is kept in unrestricted
		// mode too: it is what the panel shows as the convenient shortcuts,
		// while an unrestricted machine also accepts any absolute path with an
		// empty root.
		c.Files.Roots = []string{xrayDir, c.StateDir}
	} else if xrayDir != "" && len(strings.Split(strings.Trim(filepath.ToSlash(filepath.Clean(xrayDir)), "/"), "/")) >= 2 {
		// The xray configuration directory is always a root (named "xray"),
		// even when Roots lists other directories: the panel's Xray config
		// view reads the managed files there (PLAN v10 WP-C), and files_apply
		// already writes them. A shallow directory ("/etc") is not added: the
		// file-ops sanity check would refuse it and disable every root.
		found := false
		for _, r := range c.Files.Roots {
			if abs, err := absPath(base, r); err == nil && samePath(abs, xrayDir) {
				found = true
				break
			}
		}
		if !found {
			c.Files.Roots = append(c.Files.Roots, xrayDir)
		}
	}
	roots := make([]string, 0, len(c.Files.Roots))
	for i, r := range c.Files.Roots {
		abs, err := absPath(base, r)
		if err != nil {
			return fmt.Errorf("config: Agent.Files.Roots[%d]: %v", i, err)
		}
		roots = append(roots, abs)
	}
	// The machine token file is a credential: never reachable through a root.
	if c.Panel != nil && c.Panel.TokenFile != "" {
		excluded = append(append([]string(nil), excluded...), c.Panel.TokenFile)
	}
	excl := make([]string, 0, len(excluded))
	for _, e := range excluded {
		if e == "" {
			continue
		}
		abs, err := absPath(base, e)
		if err != nil {
			return fmt.Errorf("config: Agent.Files: %v", err)
		}
		excl = append(excl, abs)
	}
	// A root may contain agent.yml (the default xray directory does); what must
	// never happen is a root that *is* one of the excluded files, because that
	// would hand the panel a write path to the agent's own configuration or
	// state (ruling 13).
	for i, r := range roots {
		for _, e := range excl {
			if samePath(r, e) || isWithin(r, e) {
				return fmt.Errorf("config: Agent.Files.Roots[%d] %s must not contain %s: the agent's own configuration and state files are never managed", i, r, e)
			}
		}
	}
	c.Files.Roots = roots
	c.dir = base
	c.excludedFiles = excl
	return nil
}

// absPath resolves p against base when it is relative. Paths are always
// returned absolute so a later change of the process working directory cannot
// move a root.
func absPath(base, p string) (string, error) {
	if !filepath.IsAbs(p) {
		p = filepath.Join(base, p)
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	return filepath.Clean(abs), nil
}

// samePath compares two absolute paths, case-insensitively on Windows.
func samePath(a, b string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// isWithin reports whether root is file itself or sits below it.
func isWithin(root, file string) bool {
	rel, err := filepath.Rel(file, root)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// PolicySpec maps the config policy onto the agent core's policy. A nil policy
// yields the zero spec.Policy, which the core normalises to safe defaults.
func (c *Config) PolicySpec() spec.Policy {
	if c == nil || c.Policy == nil {
		return spec.Policy{}
	}
	p := c.Policy
	out := spec.Policy{
		MaxInstances:             p.MaxInstances,
		MaxPortsPerInstance:      p.MaxPortsPerInstance,
		AllowListen:              append([]string(nil), p.AllowListen...),
		PrivilegedPorts:          p.PrivilegedPorts,
		DenyPorts:                append([]int(nil), p.DenyPorts...),
		DenyCIDRs:                append([]string(nil), p.DenyCIDRs...),
		AllowPrivate:             p.AllowPrivate,
		AllowAnyTarget:           p.AllowAnyTarget,
		AllowAcceptProxyOnPublic: p.AllowAcceptProxyOnPublic,
		AllowEngines:             append([]string(nil), p.AllowEngines...),
	}
	if len(p.PortRange) == 2 {
		out.PortRange = [2]int{p.PortRange[0], p.PortRange[1]}
	}
	return out
}

// NodeControllerIDs returns the ids of the per-node overrides, sorted.
func (p *PanelConfig) NodeControllerIDs() []int {
	ids := make([]int, 0, len(p.NodeControllers))
	for id := range p.NodeControllers {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	return ids
}

// NodeControllerIDList renders the override ids as "173, 119" (ids only, never
// the configuration behind them).
func (p *PanelConfig) NodeControllerIDList() string {
	ids := p.NodeControllerIDs()
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = fmt.Sprint(id)
	}
	return strings.Join(parts, ", ")
}

// Intervals returns the pull and report intervals, defaulted and clamped.
func (p *PanelConfig) Intervals() (pull, report time.Duration) {
	return panelclient.ClampInterval(time.Duration(p.PullIntervalSec) * time.Second),
		panelclient.ClampInterval(time.Duration(p.ReportIntervalSec) * time.Second)
}

// ManifestSyncEnabled reports whether the agent syncs the signed kernel
// manifest from the panel. The default is on (a nil pointer), so an operator
// has to opt out explicitly with ManifestSync: false.
func (p *PanelConfig) ManifestSyncEnabled() bool {
	return p != nil && (p.ManifestSync == nil || *p.ManifestSync)
}

// ManifestInterval returns the manifest poll interval, defaulted (1h) and
// clamped to [5m, 24h].
func (p *PanelConfig) ManifestInterval() time.Duration {
	return panelclient.ClampManifestInterval(time.Duration(p.ManifestIntervalSec) * time.Second)
}

// Validate checks the panel section without touching the network or the token
// file (ResolveToken reads it when the link starts, and "W1nCray check" reads
// it to report problems early).
func (p *PanelConfig) Validate() error {
	if p.MachineNodes && !p.Enabled {
		return fmt.Errorf("config: Agent.Panel.MachineNodes requires Agent.Panel.Enabled")
	}
	if !p.Enabled {
		return nil
	}
	if p.MachineID <= 0 {
		return fmt.Errorf("config: Agent.Panel.MachineID must be a positive number")
	}
	switch {
	case p.Token != "" && p.TokenFile != "":
		return fmt.Errorf("config: Agent.Panel.Token and Agent.Panel.TokenFile are both set; use only one")
	case p.Token == "" && p.TokenFile == "":
		return fmt.Errorf("config: Agent.Panel needs Token or TokenFile")
	}
	if p.PullIntervalSec < 0 || p.ReportIntervalSec < 0 {
		return fmt.Errorf("config: Agent.Panel.PullIntervalSec and ReportIntervalSec must not be negative")
	}
	if p.ManifestIntervalSec < 0 {
		return fmt.Errorf("config: Agent.Panel.ManifestIntervalSec must not be negative")
	}
	// The client enforces the URL rules (https, no user info, loopback
	// exception); a placeholder token lets it check the URL alone.
	if _, err := panelclient.ValidateBaseURL(p.URL, p.AllowInsecureHTTP); err != nil {
		return fmt.Errorf("config: Agent.Panel.URL: %s", strings.TrimPrefix(err.Error(), "panelclient: "))
	}
	if p.MachineNodes {
		p.NodeController = ControllerConfigWithDefaults(p.NodeController)
	}
	// The per-node overrides are completed like the template, so a node never
	// listens on an empty address. A bad key or an empty entry is a config
	// error: silently ignoring it would leave the operator thinking the
	// override applies.
	for id, cc := range p.NodeControllers {
		if id <= 0 {
			return fmt.Errorf("config: Agent.Panel.NodeControllers: node id %d must be a positive number", id)
		}
		if cc == nil {
			return fmt.Errorf("config: Agent.Panel.NodeControllers[%d] must not be empty", id)
		}
		p.NodeControllers[id] = ControllerConfigWithDefaults(cc)
	}
	return nil
}

// ControllerConfigWithDefaults returns a fresh ControllerConfig holding src's
// fields over the node defaults. It is the one place that completes a
// ControllerConfig, so Nodes, the machine template and the per-node overrides
// all get the same treatment.
func ControllerConfigWithDefaults(src *nodecfg.Config) *nodecfg.Config {
	return nodecfg.ControllerConfigWithDefaults(src)
}

// ResolveToken returns the machine token: Token as is, or the contents of
// TokenFile (checked for safe permissions on Unix-like systems).
func (p *PanelConfig) ResolveToken() (string, error) {
	if p.Token != "" {
		return p.Token, nil
	}
	if p.TokenFile == "" {
		return "", fmt.Errorf("Agent.Panel needs Token or TokenFile")
	}
	return ReadTokenFile(p.TokenFile)
}

// MaxTokenFileBytes bounds what is read from a token file.
const MaxTokenFileBytes = 4096

// ReadTokenFile reads a token file and returns the trimmed token. The file's
// permissions are checked on the opened file, so the check cannot be raced.
func ReadTokenFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("Agent.Panel.TokenFile: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("Agent.Panel.TokenFile: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("Agent.Panel.TokenFile %s is not a regular file", path)
	}
	if err := CheckTokenFileMode(path, fi.Mode(), runtime.GOOS); err != nil {
		return "", err
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxTokenFileBytes+1))
	if err != nil {
		return "", fmt.Errorf("Agent.Panel.TokenFile: %w", err)
	}
	if len(data) > MaxTokenFileBytes {
		return "", fmt.Errorf("Agent.Panel.TokenFile %s is larger than %d bytes", path, MaxTokenFileBytes)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("Agent.Panel.TokenFile %s is empty", path)
	}
	if strings.ContainsAny(token, " \t\r\n") {
		return "", fmt.Errorf("Agent.Panel.TokenFile %s must contain just the token", path)
	}
	return token, nil
}

// CheckTokenFileMode refuses a token file that group or other can access. The
// permission bits carry no meaning on Windows (access is by ACL), so goos
// "windows" skips the check; goos is a parameter so the rule is testable.
func CheckTokenFileMode(path string, mode fs.FileMode, goos string) error {
	if goos == "windows" {
		return nil
	}
	if perm := mode.Perm(); perm&0o077 != 0 {
		return fmt.Errorf("Agent.Panel.TokenFile %s has mode %04o: it must not be accessible by group or other (run: chmod 600 %s)", path, perm, path)
	}
	return nil
}
