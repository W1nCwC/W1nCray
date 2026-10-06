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
	"github.com/W1nCwC/W1nCray/agent/spec"
	"github.com/W1nCwC/W1nCray/node"
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
	NodeController *node.Config `mapstructure:"NodeController"`
	// NodeControllers overrides NodeController for individual machine nodes,
	// keyed by the panel's node id (the same field layout as
	// Nodes[].ControllerConfig). An entry that exists is used as a whole: it is
	// never merged field by field with NodeController, so a node cannot inherit
	// a setting by accident. It is still completed with the node defaults.
	// Typical use: a node that needs PROXY protocol, its own certificate or a
	// local DNS/REALITY setup, including credentials that must stay on this
	// machine and are never sent to the panel.
	NodeControllers map[int]*node.Config `mapstructure:"NodeControllers"`
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
// directory); Unrestricted and AllowExec default to false, so the zero value is
// the safe one. Only the types and their validation live here; the behaviour is
// implemented by the later file-management package.
type FilesConfig struct {
	Roots        []string `mapstructure:"Roots"`
	Unrestricted bool     `mapstructure:"Unrestricted"`
	AllowExec    bool     `mapstructure:"AllowExec"`
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
// locally. The default is off (D8) and the panel can never relax it.
func (c *Config) TerminalEnabled() bool {
	if c == nil {
		return false
	}
	return c.Terminal == nil || c.Terminal.Enabled == nil || *c.Terminal.Enabled
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
	if len(c.Files.Roots) == 0 {
		// Default: the xray configuration directory and the agent state
		// directory, nothing else (D9).
		c.Files.Roots = []string{xrayDir, c.StateDir}
	}
	roots := make([]string, 0, len(c.Files.Roots))
	for i, r := range c.Files.Roots {
		abs, err := absPath(base, r)
		if err != nil {
			return fmt.Errorf("config: Agent.Files.Roots[%d]: %v", i, err)
		}
		roots = append(roots, abs)
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
func ControllerConfigWithDefaults(src *node.Config) *node.Config {
	cc := node.DefaultConfig()
	if src != nil {
		merge(cc, src)
	}
	return cc
}

// merge copies the set fields of src over the defaults in dst.
func merge(dst, src *node.Config) {
	defaults := *dst
	*dst = *src
	if dst.ListenIP == "" {
		dst.ListenIP = defaults.ListenIP
	}
	if dst.SendIP == "" {
		dst.SendIP = defaults.SendIP
	}
	if dst.DNSType == "" {
		dst.DNSType = defaults.DNSType
	}
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
