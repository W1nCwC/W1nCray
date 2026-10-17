// Package core assembles and runs the shared Xray instance used by all nodes.
package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/xtls/xray-core/common/serial"
	xcore "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/infra/conf"
	xjson "github.com/xtls/xray-core/infra/conf/json"

	// Register every Xray protocol, transport and app.
	_ "github.com/xtls/xray-core/main/distro/all"

	"github.com/W1nCwC/W1nCray/app/dispatcher"
	"github.com/W1nCwC/W1nCray/common/limiter"
)

// BlockTag is the tag of the blackhole outbound used by block rules.
const BlockTag = "w1ncray-block"

// upstreamDispatcherType is the TypedMessage type of Xray's dispatcher config,
// which conf.Config.Build always puts into the App list.
var upstreamDispatcherType = "xray.app.dispatcher.Config"

// ConnectionPolicy mirrors XrayR's ConnectionConfig (seconds / kB).
type ConnectionPolicy struct {
	Handshake    uint32
	ConnIdle     uint32
	UplinkOnly   uint32
	DownlinkOnly uint32
	BufferSize   int32
}

// NameServer is a DNS server bound to domains (from panel "dns" routes).
type NameServer struct {
	Address string
	Domains []string
}

// Options configures the instance.
type Options struct {
	LogLevel   string
	AccessPath string
	ErrorPath  string

	DNSConfigPath      string
	RouteConfigPath    string
	InboundConfigPath  string
	OutboundConfigPath string

	// DNSConfig, RouteConfig and OutboundConfig carry the same documents as
	// the three paths above, already in memory: the runtime profile the panel
	// delivers to a machine (handoff 44). A non-empty value wins over the
	// path, so a machine in panel mode never reads those files.
	DNSConfig      json.RawMessage
	RouteConfig    json.RawMessage
	OutboundConfig json.RawMessage

	Connection  ConnectionPolicy
	NameServers []NameServer

	// Forward, when set, prepares the instance for forwarding instances next
	// to the nodes: the fixed policy levels LevelTCPLong..LevelTCPDefault and
	// the per-inbound/outbound byte counters. Nil (the default) leaves the
	// generated config exactly as it is without forwarding.
	Forward *ForwardOptions

	// AfterStart, when set, is called by Start once the instance is running and
	// before any caller can use it. It exists for hooks that must be installed
	// after the instance's own features are up — the kernel's access-log
	// collector replaces the log handler app/log registered while the instance
	// was created, so it has to run after Start. It must not block.
	AfterStart func()
}

// Core is a running Xray instance plus handles to the features nodes use.
type Core struct {
	Instance *xcore.Instance
	Limiter  *limiter.Limiter
	Rules    *RuleManager

	conns *dispatcher.ConnTracker
	ibm   inbound.Manager
	obm   outbound.Manager
	stats stats.Manager

	// afterStart is Options.AfterStart, run by Start (see its comment).
	afterStart func()
}

// Conns returns the connection tracker. It tracks nothing until Watch is
// called with an inbound tag prefix, so node inbounds cost nothing extra.
func (c *Core) Conns() *dispatcher.ConnTracker {
	return c.conns
}

// Stats returns the stats manager of the instance. It is the manager of the
// "stats": {} section of the generated config, so it is never nil after New.
func (c *Core) Stats() stats.Manager {
	return c.stats
}

// New builds (but does not start) the Xray instance.
func New(opts Options) (*Core, error) {
	pbConfig, rm, err := compile(opts)
	if err != nil {
		return nil, err
	}
	replaced := false
	for i, app := range pbConfig.App {
		if app.Type == upstreamDispatcherType {
			pbConfig.App[i] = serial.ToTypedMessage(&dispatcher.Config{})
			replaced = true
		}
	}
	if !replaced {
		return nil, fmt.Errorf("upstream dispatcher config %q not found in app list", upstreamDispatcherType)
	}

	inst, err := xcore.New(pbConfig)
	if err != nil {
		return nil, fmt.Errorf("create xray instance: %w", err)
	}
	d, ok := inst.GetFeature(routing.DispatcherType()).(*dispatcher.Dispatcher)
	if !ok {
		inst.Close()
		return nil, fmt.Errorf("w1ncray dispatcher not installed")
	}
	l := limiter.New()
	d.SetLimiter(l)

	rm.router = inst.GetFeature(routing.RouterType()).(routing.Router)
	return &Core{
		Instance:   inst,
		Limiter:    l,
		Rules:      rm,
		conns:      d.Tracker(),
		ibm:        inst.GetFeature(inbound.ManagerType()).(inbound.Manager),
		obm:        inst.GetFeature(outbound.ManagerType()).(outbound.Manager),
		stats:      inst.GetFeature(stats.ManagerType()).(stats.Manager),
		afterStart: opts.AfterStart,
	}, nil
}

// Start starts the instance. A configured Options.AfterStart hook runs once the
// instance is up; it is not run when Start fails.
func (c *Core) Start() error {
	if err := c.Instance.Start(); err != nil {
		return err
	}
	if c.afterStart != nil {
		c.afterStart()
	}
	return nil
}

// Close stops the instance.
func (c *Core) Close() error {
	return c.Instance.Close()
}

// readJSONFile reads a JSON file that may contain comments.
func readJSONFile(path string) (json.RawMessage, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(&xjson.Reader{Reader: f})
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	b = bytes.TrimSpace(b)
	if !json.Valid(b) {
		return nil, fmt.Errorf("read %s: invalid JSON", path)
	}
	return b, nil
}

// compile builds the Xray protobuf config from opts with Xray's own config
// builder, without creating an instance.
func compile(opts Options) (*xcore.Config, *RuleManager, error) {
	cfgJSON, rm, err := buildConfig(opts)
	if err != nil {
		return nil, nil, err
	}
	var c conf.Config
	if err := json.Unmarshal(cfgJSON, &c); err != nil {
		return nil, nil, fmt.Errorf("parse xray config: %w", err)
	}
	pbConfig, err := c.Build()
	if err != nil {
		return nil, nil, fmt.Errorf("build xray config: %w", err)
	}
	return pbConfig, rm, nil
}

// Validate reports whether New would accept opts, using the same builder but
// creating nothing: no listener, no outbound, no goroutine. A caller checks a
// runtime profile with it before tearing the running instance down.
func Validate(opts Options) error {
	_, _, err := compile(opts)
	return err
}

// document returns the in-memory document when there is one, otherwise the
// content of path; name is how errors refer to it. Both empty means the
// document is not configured (nil, "", nil).
func document(mem json.RawMessage, path, kind string) (json.RawMessage, string, error) {
	if len(mem) > 0 {
		b := bytes.TrimSpace(mem)
		if !json.Valid(b) {
			return nil, "", fmt.Errorf("%s config from the panel: invalid JSON", kind)
		}
		return b, kind + " config from the panel", nil
	}
	if path == "" {
		return nil, "", nil
	}
	raw, err := readJSONFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("%s config: %w", kind, err)
	}
	return raw, kind + " config " + path, nil
}

func buildConfig(opts Options) ([]byte, *RuleManager, error) {
	cfg := map[string]any{
		"log": map[string]any{
			"loglevel": opts.LogLevel,
			"access":   opts.AccessPath,
			"error":    opts.ErrorPath,
		},
		"stats": map[string]any{},
	}

	cp := opts.Connection
	levels := map[string]any{
		"0": map[string]any{
			"handshake":         cp.Handshake,
			"connIdle":          cp.ConnIdle,
			"uplinkOnly":        cp.UplinkOnly,
			"downlinkOnly":      cp.DownlinkOnly,
			"bufferSize":        cp.BufferSize,
			"statsUserUplink":   true,
			"statsUserDownlink": true,
		},
	}
	policy := map[string]any{"levels": levels}
	if f := opts.Forward; f != nil {
		addForwardPolicy(policy, levels, cp, f)
	}
	cfg["policy"] = policy

	// DNS: local file plus panel "dns" routes.
	dns := map[string]any{}
	raw, name, err := document(opts.DNSConfig, opts.DNSConfigPath, "dns")
	if err != nil {
		return nil, nil, err
	}
	if raw != nil {
		if err := json.Unmarshal(raw, &dns); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", name, err)
		}
	}
	if len(opts.NameServers) > 0 {
		servers, _ := dns["servers"].([]any)
		extra := make([]any, 0, len(opts.NameServers)+len(servers)+1)
		for _, ns := range opts.NameServers {
			extra = append(extra, map[string]any{"address": ns.Address, "domains": ns.Domains})
		}
		if len(servers) == 0 {
			servers = []any{"localhost"}
		}
		dns["servers"] = append(extra, servers...)
	}
	if len(dns) > 0 {
		cfg["dns"] = dns
	}

	// Routing: global rules are kept by the rule manager, which orders
	// them between the per-node security rules and the per-node fallbacks.
	rm := &RuleManager{nodes: make(map[string]*NodeRules)}
	routing := map[string]any{}
	raw, name, err = document(opts.RouteConfig, opts.RouteConfigPath, "route")
	if err != nil {
		return nil, nil, err
	}
	if raw != nil {
		var rc struct {
			Rules     []json.RawMessage `json:"rules"`
			Balancers json.RawMessage   `json:"balancers"`
		}
		if err := json.Unmarshal(raw, &rc); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", name, err)
		}
		if err := json.Unmarshal(raw, &routing); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", name, err)
		}
		rm.global = rc.Rules
		rm.balancers = rc.Balancers
	}
	routing["rules"] = rm.global
	cfg["routing"] = routing

	if opts.InboundConfigPath != "" {
		raw, err := readJSONFile(opts.InboundConfigPath)
		if err != nil {
			return nil, nil, fmt.Errorf("custom inbound config: %w", err)
		}
		cfg["inbounds"] = raw
		rm.reserved = reservedInboundTags(opts.InboundConfigPath)
	}

	// Outbounds: the first custom outbound stays the default handler (as in
	// XrayR); a direct freedom outbound is the default otherwise.
	var outbounds []json.RawMessage
	raw, name, err = document(opts.OutboundConfig, opts.OutboundConfigPath, "custom outbound")
	if err != nil {
		return nil, nil, err
	}
	if raw != nil {
		if err := json.Unmarshal(raw, &outbounds); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", name, err)
		}
	}
	if len(outbounds) == 0 {
		outbounds = append(outbounds, json.RawMessage(`{"protocol":"freedom","tag":"direct"}`))
	}
	outbounds = append(outbounds, json.RawMessage(`{"protocol":"blackhole","tag":"`+BlockTag+`"}`))
	cfg["outbounds"] = outbounds

	b, err := json.Marshal(cfg)
	if err != nil {
		return nil, nil, err
	}
	return b, rm, nil
}
