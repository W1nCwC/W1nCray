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

	Connection  ConnectionPolicy
	NameServers []NameServer
}

// Core is a running Xray instance plus handles to the features nodes use.
type Core struct {
	Instance *xcore.Instance
	Limiter  *limiter.Limiter
	Rules    *RuleManager

	ibm   inbound.Manager
	obm   outbound.Manager
	stats stats.Manager
}

// New builds (but does not start) the Xray instance.
func New(opts Options) (*Core, error) {
	cfgJSON, rm, err := buildConfig(opts)
	if err != nil {
		return nil, err
	}
	var c conf.Config
	if err := json.Unmarshal(cfgJSON, &c); err != nil {
		return nil, fmt.Errorf("parse xray config: %w", err)
	}
	pbConfig, err := c.Build()
	if err != nil {
		return nil, fmt.Errorf("build xray config: %w", err)
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
		Instance: inst,
		Limiter:  l,
		Rules:    rm,
		ibm:      inst.GetFeature(inbound.ManagerType()).(inbound.Manager),
		obm:      inst.GetFeature(outbound.ManagerType()).(outbound.Manager),
		stats:    inst.GetFeature(stats.ManagerType()).(stats.Manager),
	}, nil
}

// Start starts the instance.
func (c *Core) Start() error {
	return c.Instance.Start()
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
	cfg["policy"] = map[string]any{
		"levels": map[string]any{
			"0": map[string]any{
				"handshake":         cp.Handshake,
				"connIdle":          cp.ConnIdle,
				"uplinkOnly":        cp.UplinkOnly,
				"downlinkOnly":      cp.DownlinkOnly,
				"bufferSize":        cp.BufferSize,
				"statsUserUplink":   true,
				"statsUserDownlink": true,
			},
		},
	}

	// DNS: local file plus panel "dns" routes.
	dns := map[string]any{}
	if opts.DNSConfigPath != "" {
		raw, err := readJSONFile(opts.DNSConfigPath)
		if err != nil {
			return nil, nil, fmt.Errorf("dns config: %w", err)
		}
		if err := json.Unmarshal(raw, &dns); err != nil {
			return nil, nil, fmt.Errorf("dns config %s: %w", opts.DNSConfigPath, err)
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
	if opts.RouteConfigPath != "" {
		raw, err := readJSONFile(opts.RouteConfigPath)
		if err != nil {
			return nil, nil, fmt.Errorf("route config: %w", err)
		}
		var rc struct {
			Rules     []json.RawMessage `json:"rules"`
			Balancers json.RawMessage   `json:"balancers"`
		}
		if err := json.Unmarshal(raw, &rc); err != nil {
			return nil, nil, fmt.Errorf("route config %s: %w", opts.RouteConfigPath, err)
		}
		if err := json.Unmarshal(raw, &routing); err != nil {
			return nil, nil, fmt.Errorf("route config %s: %w", opts.RouteConfigPath, err)
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
	}

	// Outbounds: the first custom outbound stays the default handler (as in
	// XrayR); a direct freedom outbound is the default otherwise.
	var outbounds []json.RawMessage
	if opts.OutboundConfigPath != "" {
		raw, err := readJSONFile(opts.OutboundConfigPath)
		if err != nil {
			return nil, nil, fmt.Errorf("custom outbound config: %w", err)
		}
		if err := json.Unmarshal(raw, &outbounds); err != nil {
			return nil, nil, fmt.Errorf("custom outbound config %s: %w", opts.OutboundConfigPath, err)
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
