package node

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/infra/conf"

	"github.com/W1nCwC/W1nCray/api/xboard"
	"github.com/W1nCwC/W1nCray/common/cert"
	"github.com/W1nCwC/W1nCray/common/limiter"
	"github.com/W1nCwC/W1nCray/core"
)

// Options configures a Controller.
type Options struct {
	API    *APIConfig
	Config *Config
	Certs  *cert.Manager
	// Reload asks the panel to rebuild the whole instance (needed when the
	// DNS app must change). It must not block.
	Reload func(reason string)
}

// Controller runs one Xboard node.
type Controller struct {
	api        *xboard.Client
	apiCfg     *APIConfig
	cfg        *Config
	certs      *cert.Manager
	reload     func(string)
	tag        string
	log        *log.Entry
	localRules []string

	core      *core.Core
	limiterIn *limiter.Inbound

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu           sync.Mutex
	pending      *xboard.NodeConfig
	pendingUsers []xboard.User
	node         *xboard.NodeConfig
	spec         *inboundSpec
	panelUsers   []xboard.User
	users        map[int]nodeUser
	inboundUp    bool
	outbounds    []string
	dnsKey       string
	dropped      map[string]int // email -> uid of removed users awaiting a last report
	pullEvery    time.Duration
	pushEvery    time.Duration
	statusOff    bool
	auto         *autoLimit

	ws      atomic.Pointer[xboard.WSClient]
	devices *deviceSignal
	started time.Time
}

// New creates a controller.
func New(opts Options) *Controller {
	a := opts.API
	nodeType := normalizeNodeType(a.NodeType, a.EnableVless)
	host := a.APIHost
	if u, err := url.Parse(a.APIHost); err == nil && u.Host != "" {
		host = u.Host
	}
	tag := fmt.Sprintf("node%d@%s", a.NodeID, host)
	// A machine runs several nodes of the same panel host, so the host cannot
	// tell them apart; the machine id can.
	if a.MachineID != 0 && a.MachineToken != "" {
		tag = fmt.Sprintf("node%d@machine%d", a.NodeID, a.MachineID)
	}
	timeout := time.Duration(a.Timeout) * time.Second
	c := &Controller{
		api: xboard.New(xboard.Config{
			APIHost:      a.APIHost,
			Key:          a.Key,
			NodeID:       a.NodeID,
			NodeType:     nodeType,
			Timeout:      timeout,
			MachineID:    a.MachineID,
			MachineToken: a.MachineToken,
		}),
		apiCfg:    a,
		cfg:       opts.Config,
		certs:     opts.Certs,
		reload:    opts.Reload,
		tag:       tag,
		log:       log.WithField("node", tag),
		users:     make(map[int]nodeUser),
		dropped:   make(map[string]int),
		pullEvery: defaultInterval,
		pushEvery: defaultInterval,
	}
	if al := c.cfg.autoSpeedLimit(); al != nil {
		c.auto = newAutoLimit(al)
	}
	c.warnDeprecated()
	return c
}

// normalizeNodeType maps XrayR NodeType values to Xboard node types.
func normalizeNodeType(t string, enableVless bool) string {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "":
		return ""
	case "v2ray":
		if enableVless {
			return protoVLESS
		}
		return protoVMess
	case "shadowsocks-plugin":
		return protoShadowsocks
	case "hysteria2":
		return protoHysteria
	default:
		return strings.ToLower(strings.TrimSpace(t))
	}
}

func (c *Controller) warnDeprecated() {
	if c.apiCfg.EnableVless || c.apiCfg.VlessFlow != "" {
		c.log.Warn("EnableVless/VlessFlow are ignored: the protocol and flow come from the panel")
	}
	if c.apiCfg.DisableCustomConfig {
		c.log.Warn("DisableCustomConfig is ignored (SSpanel only)")
	}
	if c.cfg.DisableIVCheck {
		c.log.Warn("DisableIVCheck is ignored: removed from Xray")
	}
	if len(c.cfg.GlobalDeviceLimitConfig) > 0 {
		c.log.Warn("GlobalDeviceLimitConfig is ignored: global device limits use the Xboard alive list")
	}
}

// Tag returns the inbound tag of the node.
func (c *Controller) Tag() string { return c.tag }

// Prefetch loads the node config and users before the instance is built, so
// panel DNS routes can be part of the DNS app.
func (c *Controller) Prefetch(ctx context.Context) error {
	rules, err := readRuleList(c.apiCfg.RuleListPath)
	if err != nil {
		c.log.Errorf("rule list: %v", err)
	}
	c.localRules = rules

	nc, err := c.api.GetNodeConfig(ctx)
	if err != nil {
		return fmt.Errorf("fetch node config: %w", err)
	}
	users, err := c.api.GetUsers(ctx)
	if err != nil {
		c.api.ResetETags()
		return fmt.Errorf("fetch users: %w", err)
	}
	c.mu.Lock()
	c.pending, c.pendingUsers = nc, users
	c.mu.Unlock()
	return nil
}

// NameServers returns the DNS servers of panel "dns" routes.
func (c *Controller) NameServers() []core.NameServer {
	c.mu.Lock()
	defer c.mu.Unlock()
	nc := c.pending
	if nc == nil {
		nc = c.node
	}
	if nc == nil || c.cfg.DisableGetRule {
		return nil
	}
	return dnsServers(nc.Routes)
}

func dnsKey(ns []core.NameServer) string {
	b, _ := json.Marshal(ns)
	return string(b)
}

// Start applies the prefetched config and starts the periodic tasks.
func (c *Controller) Start(cr *core.Core) error {
	c.core = cr
	c.limiterIn = cr.Limiter.AddInbound(c.tag, c.auto != nil)
	c.ctx, c.cancel = context.WithCancel(context.Background())

	c.mu.Lock()
	nc, users := c.pending, c.pendingUsers
	c.pending, c.pendingUsers = nil, nil
	// Same value NameServers() handed to the instance, so a later change of
	// the panel DNS routes (and only that) triggers a reload.
	if nc != nil && !c.cfg.DisableGetRule {
		c.dnsKey = dnsKey(dnsServers(nc.Routes))
	} else {
		c.dnsKey = dnsKey(nil)
	}
	c.mu.Unlock()

	if nc != nil {
		if err := c.applyNode(nc, users); err != nil {
			c.log.Errorf("apply node config: %v", err)
			c.api.ResetETags()
		}
	}

	c.started = time.Now()
	c.devices = newDeviceSignal()
	c.limiterIn.SetOnChange(func() { c.devices.notify(false) })
	c.wg.Add(4)
	go c.deviceReporter()
	go c.loop("pull", func() time.Duration { return c.interval(true) }, c.pull)
	go c.loop("push", func() time.Duration { return c.interval(false) }, c.push)
	go c.loop("cert", func() time.Duration { return 12 * time.Hour }, c.renewCert)
	c.startWS()
	return nil
}

func (c *Controller) interval(pull bool) time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	if pull {
		return c.pullEvery
	}
	return c.pushEvery
}

func (c *Controller) loop(name string, every func() time.Duration, fn func()) {
	defer c.wg.Done()
	t := time.NewTimer(every())
	defer t.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-t.C:
			func() {
				defer func() {
					if r := recover(); r != nil {
						c.log.Errorf("%s task panic: %v", name, r)
					}
				}()
				fn()
			}()
			t.Reset(every())
		}
	}
}

// Close stops the node, reporting the traffic not yet pushed.
func (c *Controller) Close() {
	if c.cancel == nil {
		return
	}
	c.cancel()
	c.wg.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c.reportTraffic(ctx)

	c.mu.Lock()
	defer c.mu.Unlock()
	c.teardown()
	_ = c.core.Rules.RemoveNode(c.tag)
	c.core.Limiter.RemoveInbound(c.tag)
}

// teardown removes the inbound and outbounds of the node. Caller holds c.mu.
func (c *Controller) teardown() {
	if err := c.core.RemoveInbound(c.tag); err != nil {
		c.log.Warnf("remove inbound: %v", err)
	}
	c.inboundUp = false
	for _, t := range c.outbounds {
		if err := c.core.RemoveOutbound(t); err != nil {
			c.log.Warnf("remove outbound %s: %v", t, err)
		}
	}
	c.outbounds = nil
}

func (c *Controller) pull() {
	ctx, cancel := context.WithTimeout(c.ctx, 2*time.Minute)
	defer cancel()

	nc, err := c.api.GetNodeConfig(ctx)
	if errors.Is(err, xboard.ErrNotModified) {
		nc, err = nil, nil
	}
	if err != nil {
		c.log.Errorf("fetch node config: %v", err)
		return
	}
	users, err := c.api.GetUsers(ctx)
	usersChanged := true
	if errors.Is(err, xboard.ErrNotModified) {
		users, err, usersChanged = nil, nil, false
	}
	if err != nil {
		c.log.Errorf("fetch users: %v", err)
		if nc != nil {
			c.api.ResetETags()
		}
		return
	}

	if nc != nil {
		if err := c.applyNode(nc, users); err != nil {
			c.log.Errorf("apply node config: %v", err)
			c.api.ResetETags()
		}
	} else if usersChanged {
		if err := c.applyUsers(users); err != nil {
			c.log.Errorf("apply users: %v", err)
			c.api.ResetETags()
		}
	}

	c.syncAliveList(ctx)
}

// syncAliveList fetches panel-wide device counts when some user has a limit.
func (c *Controller) syncAliveList(ctx context.Context) {
	if c.wsConnected() {
		return // exact device data arrives through sync.devices
	}
	c.mu.Lock()
	need := false
	for _, u := range c.users {
		if u.DeviceLimit > 0 {
			need = true
			break
		}
	}
	c.mu.Unlock()
	if !need {
		return
	}
	alive, err := c.api.GetAliveList(ctx)
	if err != nil {
		c.log.Debugf("fetch alive list: %v", err)
		return
	}
	c.limiterIn.SetGlobalAlive(alive)
}

// toNodeUsers applies local overrides and computes Xray identities.
func (c *Controller) toNodeUsers(p string, users []xboard.User) map[int]nodeUser {
	out := make(map[int]nodeUser, len(users))
	for _, u := range users {
		uid := int(u.ID)
		if uid <= 0 || u.UUID == "" {
			continue
		}
		mbps := float64(u.SpeedLimit)
		if c.apiCfg.SpeedLimit > 0 {
			mbps = c.apiCfg.SpeedLimit
		}
		dev := int(u.DeviceLimit)
		if c.apiCfg.DeviceLimit > 0 {
			dev = c.apiCfg.DeviceLimit
		}
		out[uid] = nodeUser{
			UID:         uid,
			UUID:        string(u.UUID),
			Email:       userEmail(p, c.tag, uid, string(u.UUID)),
			SpeedLimit:  mbpsToBytes(mbps),
			DeviceLimit: max(dev, 0),
		}
	}
	return out
}

func mbpsToBytes(mbps float64) uint64 {
	if mbps <= 0 {
		return 0
	}
	return uint64(mbps * 1000000 / 8)
}

func sortedUsers(m map[int]nodeUser) []nodeUser {
	out := make([]nodeUser, 0, len(m))
	for _, u := range m {
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UID < out[j].UID })
	return out
}

// syncLimiter pushes the user table into the limiter. Caller holds c.mu.
func (c *Controller) syncLimiter() {
	list := make([]limiter.User, 0, len(c.users))
	for _, u := range c.users {
		speed := u.SpeedLimit
		if c.auto != nil {
			if s, ok := c.auto.override(u.UID); ok {
				speed = s
			}
		}
		list = append(list, limiter.User{UID: u.UID, Email: u.Email, SpeedLimit: speed, DeviceLimit: u.DeviceLimit})
	}
	c.limiterIn.SetUsers(list)
}

// applyNode (re)creates the node from a new panel config. users == nil keeps
// the current users.
func (c *Controller) applyNode(nc *xboard.NodeConfig, users []xboard.User) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.node != nil && configKey(c.node) == configKey(nc) {
		// Same node; intervals may still differ (base_config).
		if nc.BaseConfig != nil {
			c.setIntervals(nc)
			c.node = nc
		}
		if users != nil {
			return c.applyUsersLocked(users)
		}
		return nil
	}

	p, err := checkProtocol(nc)
	if err != nil {
		c.teardown()
		c.node, c.spec = nil, nil
		return err
	}
	if c.apiCfg.NodeType != "" {
		if want := normalizeNodeType(c.apiCfg.NodeType, c.apiCfg.EnableVless); want != p {
			c.log.Warnf("NodeType %s differs from panel protocol %s; using the panel protocol", c.apiCfg.NodeType, p)
		}
	}

	if !c.cfg.DisableGetRule {
		key := dnsKey(dnsServers(nc.Routes))
		if key != c.dnsKey {
			c.dnsKey = key
			c.log.Info("panel DNS routes changed, reloading")
			c.reload("dns routes of " + c.tag + " changed")
			return nil
		}
	}

	c.setIntervals(nc)
	spec := &inboundSpec{tag: c.tag, protocol: p, node: nc, cfg: c.cfg}
	if spec.needsTLS() {
		paths, err := c.ensureCert(nc)
		if err != nil {
			return fmt.Errorf("certificate: %w", err)
		}
		spec.cert = paths
	}

	c.teardown()

	customTags, customOuts := customOutbounds(c.tag, nc.CustomOutbounds, c.log.Warnf)
	outs := append([]json.RawMessage{c.nodeOutbound()}, customOuts...)
	for _, raw := range outs {
		var oc conf.OutboundDetourConfig
		if err := json.Unmarshal(raw, &oc); err != nil {
			c.log.Warnf("outbound %s: %v", raw, err)
			continue
		}
		hc, err := oc.Build()
		if err != nil {
			c.log.Warnf("outbound %s: %v", oc.Tag, err)
			continue
		}
		if err := c.core.AddOutbound(hc); err != nil {
			c.log.Warnf("add outbound %s: %v", oc.Tag, err)
			continue
		}
		c.outbounds = append(c.outbounds, oc.Tag)
	}
	added := make(map[string]bool)
	for _, t := range c.outbounds {
		added[t] = true
	}
	for t := range customTags {
		if !added[customOutboundTag(c.tag, t)] {
			delete(customTags, t)
		}
	}

	rs := &ruleSet{
		inTag:        c.tag,
		outTag:       c.tag,
		customTags:   customTags,
		globalExists: c.core.HasOutbound,
		warn:         c.log.Warnf,
	}
	nr := rs.build(c.cfg, nc.Routes, nc.CustomRoutes, c.localRules)
	nr.Port = int(nc.ServerPort)
	if err := c.core.Rules.SetNode(c.tag, nr); err != nil {
		c.log.Errorf("panel routing rules rejected (%v); using only the built-in rules", err)
		safe := rs.build(&Config{BlockPrivateIP: c.cfg.BlockPrivateIP, DisableGetRule: true}, nil, nil, nil)
		safe.Port = int(nc.ServerPort)
		if err := c.core.Rules.SetNode(c.tag, safe); err != nil {
			return fmt.Errorf("routing rules: %w", err)
		}
	}

	if users != nil {
		c.panelUsers = users
	}
	c.users = c.toNodeUsers(p, c.panelUsers)
	c.syncLimiter()
	c.spec = spec
	c.node = nc

	if len(c.users) > 0 {
		if err := c.addInbound(); err != nil {
			return err
		}
	}
	c.log.Infof("node applied: %s on port %d, %d users", p, nc.ServerPort, len(c.users))
	return nil
}

func (c *Controller) setIntervals(nc *xboard.NodeConfig) {
	pull, push := defaultInterval, defaultInterval
	if nc.BaseConfig != nil {
		if nc.BaseConfig.PullInterval > 0 {
			pull = time.Duration(nc.BaseConfig.PullInterval) * time.Second
		}
		if nc.BaseConfig.PushInterval > 0 {
			push = time.Duration(nc.BaseConfig.PushInterval) * time.Second
		}
	}
	if c.cfg.UpdatePeriodic > 0 {
		pull = time.Duration(c.cfg.UpdatePeriodic) * time.Second
	}
	c.pullEvery, c.pushEvery = max(pull, minInterval), max(push, minInterval)
}

// nodeOutbound is the freedom outbound of the node (tag = inbound tag).
func (c *Controller) nodeOutbound() json.RawMessage {
	ds := "AsIs"
	if c.cfg.EnableDNS && c.cfg.DNSType != "" {
		ds = c.cfg.DNSType
	}
	ob := map[string]any{
		"protocol": "freedom",
		"tag":      c.tag,
		"settings": map[string]any{"domainStrategy": ds},
	}
	// Binding to 0.0.0.0 would break IPv6 destinations, so the "any"
	// addresses mean "let the system choose".
	switch c.cfg.SendIP {
	case "", "0.0.0.0", "::", "[::]":
	default:
		ob["sendThrough"] = c.cfg.SendIP
	}
	b, _ := json.Marshal(ob)
	return b
}

// addInbound builds the inbound with all current users. Caller holds c.mu.
func (c *Controller) addInbound() error {
	ic, err := c.spec.build(sortedUsers(c.users))
	if err != nil {
		return err
	}
	if err := c.core.AddInbound(ic); err != nil {
		return fmt.Errorf("add inbound: %w", err)
	}
	c.inboundUp = true
	return nil
}

func (c *Controller) applyUsers(users []xboard.User) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.applyUsersLocked(users)
}

func (c *Controller) applyUsersLocked(users []xboard.User) error {
	c.panelUsers = users
	if c.spec == nil {
		return nil
	}
	next := c.toNodeUsers(c.spec.protocol, users)
	var removed, added []nodeUser
	for uid, old := range c.users {
		if nu, ok := next[uid]; !ok || nu.UUID != old.UUID {
			removed = append(removed, old)
		}
	}
	for uid, nu := range next {
		if old, ok := c.users[uid]; !ok || old.UUID != nu.UUID {
			added = append(added, nu)
		}
	}
	prev := c.users
	c.users = next
	c.syncLimiter()
	for _, u := range removed {
		if _, still := next[u.UID]; !still {
			c.dropped[u.Email] = u.UID
		}
	}
	if len(removed) == 0 && len(added) == 0 {
		return nil
	}

	var err error
	switch {
	case len(next) == 0:
		err = c.core.RemoveInbound(c.tag)
		c.inboundUp = false
	case !c.inboundUp:
		err = c.addInbound()
	case !hotUsers(c.spec.protocol):
		if err = c.core.RemoveInbound(c.tag); err == nil {
			c.inboundUp = false
			err = c.addInbound()
		}
	default:
		if err = c.hotUpdate(removed, added); err != nil {
			// A partial hot update leaves the inbound out of sync with
			// any user table we could restore; rebuild it instead.
			c.log.Warnf("hot user update failed (%v), rebuilding inbound", err)
			if err = c.core.RemoveInbound(c.tag); err == nil {
				c.inboundUp = false
				err = c.addInbound()
			}
		}
	}
	if err != nil {
		c.users = prev
		c.syncLimiter()
		return err
	}
	c.log.Infof("users: %d removed, %d added, %d total", len(removed), len(added), len(next))
	return nil
}

func (c *Controller) hotUpdate(removed, added []nodeUser) error {
	if len(removed) > 0 {
		emails := make([]string, len(removed))
		for i, u := range removed {
			emails[i] = u.Email
		}
		if err := c.core.RemoveUsers(c.tag, emails); err != nil {
			return err
		}
	}
	if len(added) > 0 {
		sort.Slice(added, func(i, j int) bool { return added[i].UID < added[j].UID })
		pu, err := c.spec.protocolUsers(added)
		if err != nil {
			return err
		}
		if err := c.core.AddUsers(c.tag, pu); err != nil {
			return err
		}
	}
	return nil
}

// certConfig resolves the certificate source: panel cert_config first, then
// the local CertConfig.
func (c *Controller) certConfig(nc *xboard.NodeConfig) *cert.Config {
	t := nc.TLSConfig()
	domain := string(t.ServerName)
	if domain == "" {
		domain = string(nc.ServerName)
	}
	if domain == "" {
		domain = string(nc.Host)
	}
	local := c.cfg.CertConfig

	if pc := nc.CertConfig; pc != nil && pc.CertMode != "" && pc.CertMode != cert.ModeNone {
		cc := &cert.Config{
			CertMode:    strings.ToLower(string(pc.CertMode)),
			CertDomain:  string(pc.Domain),
			CertFile:    string(pc.CertFile),
			KeyFile:     string(pc.KeyFile),
			Provider:    string(pc.DNSProvider),
			Email:       string(pc.Email),
			HTTPPort:    int(pc.HTTPPort),
			CertContent: string(pc.CertContent),
			KeyContent:  string(pc.KeyContent),
		}
		if len(pc.DNSEnv) > 0 {
			cc.DNSEnv = make(map[string]string, len(pc.DNSEnv))
			for k, v := range pc.DNSEnv {
				cc.DNSEnv[k] = string(v)
			}
		}
		if cc.CertDomain == "" {
			cc.CertDomain = domain
		}
		if local != nil {
			if cc.CertDomain == "" {
				cc.CertDomain = local.CertDomain
			}
			if cc.Email == "" {
				cc.Email = local.Email
			}
			if cc.Provider == "" {
				cc.Provider = local.Provider
			}
			if cc.DNSEnv == nil {
				cc.DNSEnv = local.DNSEnv
			}
			if cc.CertMode == cert.ModeFile && cc.CertFile == "" {
				cc.CertFile, cc.KeyFile = local.CertFile, local.KeyFile
			}
			cc.RejectUnknownSni = local.RejectUnknownSni
		}
		return cc
	}
	if local.Enabled() {
		cc := *local
		if cc.CertDomain == "" {
			cc.CertDomain = domain
		}
		return &cc
	}
	return nil
}

func (c *Controller) ensureCert(nc *xboard.NodeConfig) (*certPaths, error) {
	cc := c.certConfig(nc)
	if cc == nil {
		return nil, errors.New("TLS is enabled but no certificate is configured (set cert_config in the panel or CertConfig locally)")
	}
	cf, kf, renewed, err := c.certs.Ensure(cc)
	if err != nil {
		return nil, err
	}
	if renewed {
		c.log.Infof("certificate for %s written (%s mode)", cc.CertDomain, cc.CertMode)
	}
	return &certPaths{CertFile: cf, KeyFile: kf, RejectUnknownSNI: cc.RejectUnknownSni}, nil
}

func (c *Controller) renewCert() {
	c.mu.Lock()
	nc, spec := c.node, c.spec
	c.mu.Unlock()
	if nc == nil || spec == nil || !spec.needsTLS() {
		return
	}
	// Ensure only writes new files when the certificate is missing, changed
	// or close to expiry; Xray reloads the files on its own.
	if _, err := c.ensureCert(nc); err != nil {
		c.log.Errorf("renew certificate: %v", err)
	}
}
