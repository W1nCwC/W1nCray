// Package panel loads the W1nCray config and runs the Xray instance with one
// controller per configured Xboard node.
package panel

import (
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

// Config is the root of config.yml (XrayR compatible layout).
type Config struct {
	LogConfig          *LogConfig        `mapstructure:"Log"`
	DnsConfigPath      string            `mapstructure:"DnsConfigPath"`
	RouteConfigPath    string            `mapstructure:"RouteConfigPath"`
	InboundConfigPath  string            `mapstructure:"InboundConfigPath"`
	OutboundConfigPath string            `mapstructure:"OutboundConfigPath"`
	ConnectionConfig   *ConnectionConfig `mapstructure:"ConnectionConfig"`
	CertDir            string            `mapstructure:"CertDir"`
	NodesConfig        []*NodesConfig    `mapstructure:"Nodes"`
	Agent              *AgentConfig      `mapstructure:"Agent"`
}

// AgentConfig configures the in-process agent: a declarative kernel manager
// that applies a desired state (from Agent.DesiredPath) to the configured
// engines. It is independent of the Xboard Nodes; either may be configured.
type AgentConfig struct {
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
	Policy *AgentPolicy `mapstructure:"Policy"`
	// Panel links the agent to a panel (W1nCBoard/Xboard) that pushes the
	// desired state and receives the status reports. It requires the agent to
	// be enabled and never relaxes Policy.
	Panel *AgentPanelConfig `mapstructure:"Panel"`
}

// AgentPanelConfig configures the agent <-> panel link (the wire contract is
// docs/PLAN-v7-panel-control.md). The agent connects out to the panel; the
// panel never connects to the agent.
type AgentPanelConfig struct {
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

// AgentPolicy maps agent/spec.Policy fields onto the config file. A zero value
// keeps the agent defaults (loopback-only listeners, ports >= 1024, ...).
type AgentPolicy struct {
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

// NodesConfig is one entry of Nodes.
type NodesConfig struct {
	PanelType        string          `mapstructure:"PanelType"`
	ApiConfig        *node.APIConfig `mapstructure:"ApiConfig"`
	ControllerConfig *node.Config    `mapstructure:"ControllerConfig"`
}

// LogConfig configures logging.
type LogConfig struct {
	Level      string `mapstructure:"Level"`
	AccessPath string `mapstructure:"AccessPath"`
	ErrorPath  string `mapstructure:"ErrorPath"`
}

// ConnectionConfig is the Xray level-0 policy (seconds / kB).
type ConnectionConfig struct {
	Handshake    uint32 `mapstructure:"Handshake"`
	ConnIdle     uint32 `mapstructure:"ConnIdle"`
	UplinkOnly   uint32 `mapstructure:"UplinkOnly"`
	DownlinkOnly uint32 `mapstructure:"DownlinkOnly"`
	BufferSize   int32  `mapstructure:"BufferSize"`
}

// LoadConfig reads and validates a config file.
func LoadConfig(path string) (*Config, error) {
	v := viper.New()
	v.SetConfigFile(path)
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yml", ".yaml", ".json", ".toml":
	default:
		v.SetConfigType("yaml")
	}
	// XrayR defaults.
	v.SetDefault("Log.Level", "warning")
	v.SetDefault("ConnectionConfig.Handshake", 4)
	v.SetDefault("ConnectionConfig.ConnIdle", 30)
	v.SetDefault("ConnectionConfig.UplinkOnly", 2)
	v.SetDefault("ConnectionConfig.DownlinkOnly", 4)
	v.SetDefault("ConnectionConfig.BufferSize", 64)
	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	cfg := new(Config)
	if err := v.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	cfg.resolvePaths(path)
	return cfg, nil
}

// resolvePaths fills the agent's path defaults relative to the config file.
// It runs after validate so it never hides a config error.
func (c *Config) resolvePaths(configPath string) {
	if c.Agent == nil {
		return
	}
	base := filepath.Dir(configPath)
	if c.Agent.StateDir == "" {
		c.Agent.StateDir = filepath.Join(base, "state")
	}
	if c.Agent.KernelsDir == "" {
		c.Agent.KernelsDir = filepath.Join(c.Agent.StateDir, "kernels")
	}
	if pc := c.Agent.Panel; pc != nil && pc.TokenFile != "" && !filepath.IsAbs(pc.TokenFile) {
		pc.TokenFile = filepath.Join(base, pc.TokenFile)
	}
}

func (c *Config) validate() error {
	if c.LogConfig == nil {
		c.LogConfig = &LogConfig{Level: "warning"}
	}
	if c.ConnectionConfig == nil {
		c.ConnectionConfig = &ConnectionConfig{Handshake: 4, ConnIdle: 30, UplinkOnly: 2, DownlinkOnly: 4, BufferSize: 64}
	}
	// D-F: a machine may run the agent without any Xboard node, so an empty
	// Nodes list is only an error when neither Nodes nor the agent is enabled.
	// Machine mode (Agent.Panel.MachineNodes) needs the agent, so it is covered
	// by the same rule.
	if len(c.NodesConfig) == 0 && (c.Agent == nil || !c.Agent.Enabled) {
		return fmt.Errorf("config: no Nodes configured and Agent.Enabled is not set (configure Nodes, or an Agent)")
	}
	if c.Agent != nil {
		if err := c.Agent.validate(); err != nil {
			return err
		}
	}
	seen := make(map[string]bool)
	for i, n := range c.NodesConfig {
		if n == nil || n.ApiConfig == nil {
			return fmt.Errorf("config: Nodes[%d]: missing ApiConfig", i)
		}
		switch strings.ToLower(n.PanelType) {
		case "", "xboard", "newv2board", "v2board":
		default:
			return fmt.Errorf("config: Nodes[%d]: unsupported PanelType %q (W1nCray supports Xboard)", i, n.PanelType)
		}
		a := n.ApiConfig
		if a.APIHost == "" || a.Key == "" || a.NodeID <= 0 {
			return fmt.Errorf("config: Nodes[%d]: ApiHost, ApiKey and NodeID are required", i)
		}
		key := fmt.Sprintf("%s#%d", strings.TrimRight(a.APIHost, "/"), a.NodeID)
		if seen[key] {
			return fmt.Errorf("config: Nodes[%d]: node %d of %s is configured twice", i, a.NodeID, a.APIHost)
		}
		seen[key] = true

		n.ControllerConfig = controllerConfigWithDefaults(n.ControllerConfig)
	}
	return nil
}

// controllerConfigWithDefaults returns a fresh ControllerConfig holding src's
// fields over the node defaults. It is the one place that completes a
// ControllerConfig, so Nodes, the machine template and the per-node overrides
// all get the same treatment.
func controllerConfigWithDefaults(src *node.Config) *node.Config {
	cc := node.DefaultConfig()
	if src != nil {
		merge(cc, src)
	}
	return cc
}

// nodeControllerIDs returns the ids of the per-node overrides, sorted.
func (p *AgentPanelConfig) nodeControllerIDs() []int {
	ids := make([]int, 0, len(p.NodeControllers))
	for id := range p.NodeControllers {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	return ids
}

// nodeControllerIDList renders the override ids as "173, 119" (ids only, never
// the configuration behind them).
func (p *AgentPanelConfig) nodeControllerIDList() string {
	parts := make([]string, len(p.NodeControllers))
	for i, id := range p.nodeControllerIDs() {
		parts[i] = fmt.Sprint(id)
	}
	return strings.Join(parts, ", ")
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

// validate checks the agent section. It is deliberately shallow: the policy is
// parsed in full by the agent core when a desired state is applied.
func (a *AgentConfig) validate() error {
	if !a.Enabled {
		if a.Panel != nil && (a.Panel.Enabled || a.Panel.MachineNodes) {
			return fmt.Errorf("config: Agent.Panel.Enabled requires Agent.Enabled")
		}
		return nil
	}
	if a.Panel != nil {
		if err := a.Panel.validate(); err != nil {
			return err
		}
	}
	if a.Policy != nil {
		if n := len(a.Policy.PortRange); n != 0 && n != 2 {
			return fmt.Errorf("config: Agent.Policy.PortRange must have two elements [lo, hi], got %d", n)
		}
		for _, e := range a.Policy.AllowEngines {
			switch e {
			case spec.EngineAuto, spec.EngineXray, spec.EngineGost, spec.EngineFrp, spec.EngineRealm:
			default:
				return fmt.Errorf("config: Agent.Policy.AllowEngines: unknown engine %q", e)
			}
		}
	}
	return nil
}

// PolicySpec maps the config policy onto the agent core's policy. A nil policy
// yields the zero spec.Policy, which the core normalises to safe defaults.
func (a *AgentConfig) PolicySpec() spec.Policy {
	if a == nil || a.Policy == nil {
		return spec.Policy{}
	}
	p := a.Policy
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

// Intervals returns the pull and report intervals, defaulted and clamped.
func (p *AgentPanelConfig) Intervals() (pull, report time.Duration) {
	return panelclient.ClampInterval(time.Duration(p.PullIntervalSec) * time.Second),
		panelclient.ClampInterval(time.Duration(p.ReportIntervalSec) * time.Second)
}

// ManifestSyncEnabled reports whether the agent syncs the signed kernel
// manifest from the panel. The default is on (a nil pointer), so an operator
// has to opt out explicitly with ManifestSync: false.
func (p *AgentPanelConfig) ManifestSyncEnabled() bool {
	return p != nil && (p.ManifestSync == nil || *p.ManifestSync)
}

// ManifestInterval returns the manifest poll interval, defaulted (1h) and
// clamped to [5m, 24h].
func (p *AgentPanelConfig) ManifestInterval() time.Duration {
	return panelclient.ClampManifestInterval(time.Duration(p.ManifestIntervalSec) * time.Second)
}

// validate checks the panel section without touching the network or the token
// file (ResolveToken reads it when the link starts, and "W1nCray check" reads
// it to report problems early).
func (p *AgentPanelConfig) validate() error {
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
	if _, err := panelclient.New(panelclient.Options{
		BaseURL:           p.URL,
		MachineID:         p.MachineID,
		Token:             "-",
		AllowInsecureHTTP: p.AllowInsecureHTTP,
	}); err != nil {
		return fmt.Errorf("config: Agent.Panel.URL: %s", strings.TrimPrefix(err.Error(), "panelclient: "))
	}
	if p.MachineNodes {
		p.NodeController = controllerConfigWithDefaults(p.NodeController)
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
		p.NodeControllers[id] = controllerConfigWithDefaults(cc)
	}
	return nil
}

// machinePanel returns the panel section when machine mode is on: the panel
// then owns the node list, and each node gets NodeControllers[id] when it is
// set, otherwise the NodeController template.
func machinePanel(cfg *Config) *AgentPanelConfig {
	if cfg.Agent == nil || !cfg.Agent.Enabled || cfg.Agent.Panel == nil {
		return nil
	}
	pc := cfg.Agent.Panel
	if !pc.Enabled || !pc.MachineNodes {
		return nil
	}
	return pc
}

// ResolveToken returns the machine token: Token as is, or the contents of
// TokenFile (checked for safe permissions on Unix-like systems).
func (p *AgentPanelConfig) ResolveToken() (string, error) {
	if p.Token != "" {
		return p.Token, nil
	}
	if p.TokenFile == "" {
		return "", fmt.Errorf("Agent.Panel needs Token or TokenFile")
	}
	return readTokenFile(p.TokenFile)
}

// maxTokenFileBytes bounds what is read from a token file.
const maxTokenFileBytes = 4096

// readTokenFile reads a token file and returns the trimmed token. The file's
// permissions are checked on the opened file, so the check cannot be raced.
func readTokenFile(path string) (string, error) {
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
	if err := checkTokenFileMode(path, fi.Mode(), runtime.GOOS); err != nil {
		return "", err
	}
	data, err := io.ReadAll(io.LimitReader(f, maxTokenFileBytes+1))
	if err != nil {
		return "", fmt.Errorf("Agent.Panel.TokenFile: %w", err)
	}
	if len(data) > maxTokenFileBytes {
		return "", fmt.Errorf("Agent.Panel.TokenFile %s is larger than %d bytes", path, maxTokenFileBytes)
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

// checkTokenFileMode refuses a token file that group or other can access. The
// permission bits carry no meaning on Windows (access is by ACL), so goos
// "windows" skips the check; goos is a parameter so the rule is testable.
func checkTokenFileMode(path string, mode fs.FileMode, goos string) error {
	if goos == "windows" {
		return nil
	}
	if perm := mode.Perm(); perm&0o077 != 0 {
		return fmt.Errorf("Agent.Panel.TokenFile %s has mode %04o: it must not be accessible by group or other (run: chmod 600 %s)", path, perm, path)
	}
	return nil
}
