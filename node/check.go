package node

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/xtls/xray-core/infra/conf"

	"github.com/W1nCwC/W1nCray/api/xboard"
	"github.com/W1nCwC/W1nCray/common/cert"
)

// Check fetches the node from the panel and builds its inbound, outbounds and
// rules without listening or requesting certificates. It returns a summary.
func (c *Controller) Check(ctx context.Context) (string, error) {
	if err := c.Prefetch(ctx); err != nil {
		return "", err
	}
	c.mu.Lock()
	nc, users := c.pending, c.pendingUsers
	c.mu.Unlock()

	p, err := checkProtocol(nc)
	if err != nil {
		return "", err
	}
	spec := &inboundSpec{tag: c.tag, protocol: p, node: nc, cfg: c.cfg}
	var notes []string
	security := "无 TLS"
	switch {
	case spec.useREALITY():
		security = "REALITY"
	case spec.needsTLS():
		security = "TLS"
		paths, note, cleanup, err := c.checkCert(nc)
		defer cleanup()
		if err != nil {
			return "", err
		}
		if note != "" {
			notes = append(notes, note)
		}
		spec.cert = paths
	}

	nu := sortedUsers(c.toNodeUsers(p, users))
	if len(nu) == 0 {
		notes = append(notes, "面板当前没有可用用户，入站会在有用户后创建")
		nu = []nodeUser{{UID: 1, UUID: "00000000-0000-0000-0000-000000000000", Email: userEmail(p, c.tag, 1, "00000000-0000-0000-0000-000000000000")}}
	}
	if _, err := spec.build(nu); err != nil {
		return "", fmt.Errorf("入站: %w", err)
	}

	customTags, outs := customOutbounds(c.tag, nc.CustomOutbounds, func(f string, a ...any) { notes = append(notes, fmt.Sprintf(f, a...)) })
	for _, raw := range outs {
		var oc conf.OutboundDetourConfig
		if err := json.Unmarshal(raw, &oc); err != nil {
			return "", fmt.Errorf("custom_outbounds: %w", err)
		}
		if _, err := oc.Build(); err != nil {
			return "", fmt.Errorf("custom_outbounds %s: %w", oc.Tag, err)
		}
	}
	rs := &ruleSet{inTag: c.tag, outTag: c.tag, customTags: customTags,
		warn: func(f string, a ...any) { notes = append(notes, fmt.Sprintf(f, a...)) }}
	nr := rs.build(c.cfg, nc.Routes, nc.CustomRoutes, c.localRules)
	rc := &conf.RouterConfig{RuleList: append(nr.Head, nr.Tail...)}
	if pb, err := rc.Build(); err != nil {
		return "", fmt.Errorf("路由规则: %w", err)
	} else {
		for i, r := range pb.Rule {
			if _, err := r.BuildCondition(); err != nil {
				return "", fmt.Errorf("路由规则 %d: %w", i, err)
			}
		}
	}
	if ns := dnsServers(nc.Routes); len(ns) > 0 && !c.cfg.DisableGetRule {
		notes = append(notes, fmt.Sprintf("面板 DNS 路由 %d 条", len(ns)))
	}

	s := fmt.Sprintf("%s 端口 %d，%s，用户 %d 个", p, nc.ServerPort, security, len(users))
	if len(notes) > 0 {
		s += "\n      " + strings.Join(notes, "\n      ")
	}
	return s, nil
}

// checkCert finds the certificate the node would use. When it does not exist
// yet (it is obtained at start), a temporary self-signed one stands in so the
// rest of the TLS settings can still be validated; cleanup removes it.
func (c *Controller) checkCert(nc *xboard.NodeConfig) (paths *certPaths, note string, cleanup func(), err error) {
	cleanup = func() {}
	cc := c.certConfig(nc)
	if cc == nil {
		return nil, "", cleanup, fmt.Errorf("TLS 已启用但未配置证书（面板 cert_config 或本地 CertConfig）")
	}
	cf, kf := cert.TargetPaths(c.certs.Dir, cc)
	if _, err := tls.LoadX509KeyPair(cf, kf); err == nil {
		return &certPaths{CertFile: cf, KeyFile: kf, RejectUnknownSNI: cc.RejectUnknownSni}, "证书: " + cf, cleanup, nil
	}
	switch cc.CertMode {
	case cert.ModeFile:
		return nil, "", cleanup, fmt.Errorf("证书文件不可用: %s / %s", cf, kf)
	case cert.ModeContent:
		if _, err := tls.X509KeyPair([]byte(cc.CertContent), []byte(cc.KeyContent)); err != nil {
			return nil, "", cleanup, fmt.Errorf("面板下发的证书无效: %w", err)
		}
	}
	dir, err := os.MkdirTemp("", "w1ncray-check")
	if err != nil {
		return nil, "", cleanup, err
	}
	cleanup = func() { os.RemoveAll(dir) }
	certPEM, keyPEM, err := cert.SelfSigned("check.invalid", time.Hour)
	if err != nil {
		return nil, "", cleanup, err
	}
	paths = &certPaths{CertFile: filepath.Join(dir, "c.crt"), KeyFile: filepath.Join(dir, "c.key")}
	os.WriteFile(paths.CertFile, certPEM, 0o600)
	os.WriteFile(paths.KeyFile, keyPEM, 0o600)
	return paths, fmt.Sprintf("证书尚不存在，启动时以 %s 模式为 %s 获取", cc.CertMode, cc.CertDomain), cleanup, nil
}
