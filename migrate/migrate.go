// Package migrate converts an XrayR installation (config.yml and the files it
// references) into a W1nCray configuration. The XrayR directory is only read.
//
// Only unambiguous conversions are applied; JSON files are copied verbatim and
// checked afterwards with the new kernel (see `W1nCray check`).
package migrate

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	yaml "go.yaml.in/yaml/v3"

	"github.com/W1nCwC/W1nCray/common/certcfg"
)

// Options configures a migration.
type Options struct {
	From   string // XrayR directory or its config.yml
	To     string // W1nCray directory
	DryRun bool
	Force  bool // overwrite existing files in To
	// SearchDirs are extra places for geo files and XrayR ACME certificates.
	SearchDirs []string
}

// DefaultSearchDirs are the usual XrayR/Xray install locations.
var DefaultSearchDirs = []string{"/usr/local/XrayR", "/usr/local/share/xray", "/usr/share/xray"}

// Copy is a file copied from the XrayR side.
type Copy struct {
	From, To string
	Skipped  string // reason when not copied
}

// Report describes what a migration did (or would do in dry-run mode).
type Report struct {
	Source   string
	Config   string
	Copies   []Copy
	Changes  []string
	Warnings []string
}

func (r *Report) change(format string, a ...any) {
	r.Changes = append(r.Changes, fmt.Sprintf(format, a...))
}
func (r *Report) warn(format string, a ...any) {
	r.Warnings = append(r.Warnings, fmt.Sprintf(format, a...))
}

// String renders the report for the terminal (Chinese, like the docs).
func (r *Report) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "来源: %s\n目标配置: %s\n", r.Source, r.Config)
	if len(r.Changes) > 0 {
		b.WriteString("配置转换:\n")
		for _, c := range r.Changes {
			fmt.Fprintf(&b, "  - %s\n", c)
		}
	}
	if len(r.Copies) > 0 {
		b.WriteString("文件:\n")
		for _, c := range r.Copies {
			if c.Skipped != "" {
				fmt.Fprintf(&b, "  - 跳过 %s（%s）\n", c.From, c.Skipped)
			} else {
				fmt.Fprintf(&b, "  - %s -> %s\n", c.From, c.To)
			}
		}
	}
	if len(r.Warnings) > 0 {
		b.WriteString("注意:\n")
		for _, w := range r.Warnings {
			fmt.Fprintf(&b, "  ! %s\n", w)
		}
	}
	return b.String()
}

// Keys whose values are files W1nCray reads (copied when inside the XrayR dir).
var fileKeys = map[string]bool{
	"DnsConfigPath": true, "RouteConfigPath": true, "InboundConfigPath": true,
	"OutboundConfigPath": true, "RuleListPath": true, "CertFile": true, "KeyFile": true,
}

// Keys whose values are paths W1nCray writes (rewritten, not copied).
var logKeys = map[string]bool{"AccessPath": true, "ErrorPath": true}

// Files of a default XrayR install, copied even when not referenced.
var knownFiles = []string{"dns.json", "route.json", "custom_inbound.json", "custom_outbound.json", "rulelist"}

var geoFiles = []string{"geoip.dat", "geosite.dat"}

type migration struct {
	opts    Options
	fromDir string
	toDir   string
	report  *Report
	planned map[string]string // target -> source
	order   []string
	origin  map[string]string // rewritten path -> XrayR path
	// realityNote is set when some node relied on XrayR ignoring the panel
	// REALITY settings (see convertNode).
	realityNote bool
}

// Run performs the migration.
func Run(opts Options) (*Report, error) {
	if opts.From == "" || opts.To == "" {
		return nil, errors.New("both source and target are required")
	}
	if opts.SearchDirs == nil {
		opts.SearchDirs = DefaultSearchDirs
	}
	srcConfig := opts.From
	if st, err := os.Stat(srcConfig); err == nil && st.IsDir() {
		srcConfig = filepath.Join(srcConfig, "config.yml")
	}
	raw, err := os.ReadFile(srcConfig)
	if err != nil {
		return nil, fmt.Errorf("read XrayR config: %w", err)
	}
	fromDir, err := filepath.Abs(filepath.Dir(srcConfig))
	if err != nil {
		return nil, err
	}
	toDir, err := filepath.Abs(opts.To)
	if err != nil {
		return nil, err
	}
	if samePath(fromDir, toDir) {
		return nil, errors.New("source and target directories are the same")
	}
	m := &migration{
		opts:    opts,
		fromDir: fromDir,
		toDir:   toDir,
		report:  &Report{Source: srcConfig, Config: filepath.Join(toDir, "config.yml")},
		planned: make(map[string]string),
		origin:  make(map[string]string),
	}
	if _, err := os.Stat(m.report.Config); err == nil && !opts.Force {
		return nil, fmt.Errorf("%s already exists (use --force to overwrite)", m.report.Config)
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse XrayR config: %w", err)
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("XrayR config is not a YAML mapping")
	}
	root := doc.Content[0]
	if err := m.convert(root); err != nil {
		return nil, err
	}
	m.planKnownFiles()

	var out bytes.Buffer
	fmt.Fprintf(&out, "# Migrated from XrayR (%s) by `W1nCray migrate` on %s\n", srcConfig, time.Now().Format("2006-01-02 15:04:05"))
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, err
	}
	enc.Close()

	if err := m.execute(out.Bytes()); err != nil {
		return nil, err
	}
	return m.report, nil
}

func samePath(a, b string) bool {
	return filepath.Clean(a) == filepath.Clean(b)
}

// rewrite maps a path inside the XrayR dir to the W1nCray dir.
func (m *migration) rewrite(p string) (string, bool) {
	if p == "" {
		return p, false
	}
	clean := filepath.ToSlash(filepath.Clean(p))
	from := filepath.ToSlash(m.fromDir)
	if clean == from {
		return filepath.ToSlash(m.toDir), true
	}
	if strings.HasPrefix(clean, from+"/") {
		return filepath.ToSlash(m.toDir) + clean[len(from):], true
	}
	return p, false
}

func (m *migration) plan(src, dst string) {
	if _, ok := m.planned[dst]; ok {
		return
	}
	m.planned[dst] = src
	m.order = append(m.order, dst)
}

// convert walks the document, rewriting paths and converting nodes.
func (m *migration) convert(root *yaml.Node) error {
	m.walk(root)
	nodes := mapGet(root, "Nodes")
	if nodes == nil || nodes.Kind != yaml.SequenceNode || len(nodes.Content) == 0 {
		return errors.New("XrayR config has no Nodes")
	}
	kept := nodes.Content[:0]
	for i, n := range nodes.Content {
		if n.Kind != yaml.MappingNode {
			continue
		}
		if !m.convertNode(i, n) {
			continue
		}
		kept = append(kept, n)
	}
	nodes.Content = kept
	if m.realityNote {
		m.report.warn("XrayR 仅在 DisableLocalREALITYConfig: true 时使用面板 REALITY；W1nCray 在面板节点 tls=2 时直接使用面板 REALITY 配置")
	}
	if len(kept) == 0 {
		return errors.New("no XrayR node uses a supported panel (V2board/NewV2board/Xboard)")
	}
	return nil
}

// walk rewrites path values and comments that point into the XrayR dir.
func (m *migration) walk(n *yaml.Node) {
	m.rewriteComments(n)
	switch n.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for _, c := range n.Content {
			m.walk(c)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			m.rewriteComments(k)
			if v.Kind == yaml.ScalarNode && v.Tag == "!!str" && (fileKeys[k.Value] || logKeys[k.Value]) {
				m.convertPath(k.Value, v)
			}
			m.walk(v)
		}
	}
}

func (m *migration) convertPath(key string, v *yaml.Node) {
	newPath, inside := m.rewrite(v.Value)
	if !inside {
		if fileKeys[key] && filepath.IsAbs(v.Value) {
			m.report.warn("%s: %s 不在 XrayR 目录内，保留原路径（请确认 W1nCray 有权限读取）", key, v.Value)
		}
		return
	}
	if fileKeys[key] {
		m.origin[newPath] = v.Value
		if _, err := os.Stat(v.Value); err == nil {
			m.plan(v.Value, filepath.FromSlash(newPath))
		} else if key != "CertFile" && key != "KeyFile" {
			// Certificate paths are checked per CertMode (ACME ignores them).
			m.report.warn("%s: 引用的文件 %s 不存在", key, v.Value)
		}
	}
	m.report.change("%s: %s -> %s", key, v.Value, newPath)
	v.Value = newPath
}

func (m *migration) rewriteComments(n *yaml.Node) {
	from := filepath.ToSlash(m.fromDir)
	to := filepath.ToSlash(m.toDir)
	for _, c := range []*string{&n.HeadComment, &n.LineComment, &n.FootComment} {
		if strings.Contains(*c, from) {
			*c = strings.ReplaceAll(*c, from, to)
		}
	}
}

// convertNode converts one entry of Nodes; false drops the entry.
func (m *migration) convertNode(i int, n *yaml.Node) bool {
	label := fmt.Sprintf("Nodes[%d]", i)
	api := mapGet(n, "ApiConfig")
	if api != nil {
		if id := mapGet(api, "NodeID"); id != nil {
			label += " (NodeID " + id.Value + ")"
		}
	}

	if pt := mapGet(n, "PanelType"); pt != nil {
		switch strings.ToLower(pt.Value) {
		case "newv2board", "v2board":
			m.report.change("%s: PanelType %s -> Xboard", label, pt.Value)
			pt.Value = "Xboard"
		case "xboard", "":
		default:
			m.report.warn("%s: PanelType %s 不受支持（W1nCray 仅对接 Xboard），已从迁移结果中移除", label, pt.Value)
			return false
		}
	}

	if api != nil {
		enableVless := false
		if ev := mapGet(api, "EnableVless"); ev != nil {
			enableVless = strings.EqualFold(ev.Value, "true")
		}
		if nt := mapGet(api, "NodeType"); nt != nil && nt.Value != "" {
			if conv := nodeType(nt.Value, enableVless); conv != nt.Value {
				m.report.change("%s: NodeType %s%s -> %s", label, nt.Value, map[bool]string{true: " + EnableVless", false: ""}[enableVless], conv)
				nt.Value = conv
			}
		}
		for _, k := range []string{"EnableVless", "VlessFlow", "DisableCustomConfig"} {
			if mapDelete(api, k) {
				m.report.change("%s: 删除已废弃的 ApiConfig.%s（协议与 flow 以面板为准）", label, k)
			}
		}
	}

	cc := mapGet(n, "ControllerConfig")
	if cc == nil {
		return true
	}
	if v := mapGet(cc, "DisableLocalREALITYConfig"); v != nil {
		if strings.EqualFold(v.Value, "true") {
			// XrayR used the panel REALITY settings only with this flag;
			// W1nCray uses them by default and EnableREALITY means "local".
			mapSet(cc, "EnableREALITY", "false", "!!bool")
			m.report.change("%s: DisableLocalREALITYConfig: true -> EnableREALITY: false（使用面板 REALITY 配置）", label)
		}
		mapDelete(cc, "DisableLocalREALITYConfig")
	} else if er := mapGet(cc, "EnableREALITY"); er == nil || !strings.EqualFold(er.Value, "true") {
		m.realityNote = true
	}
	if mapDelete(cc, "DisableIVCheck") {
		m.report.change("%s: 删除 DisableIVCheck（Xray 已移除该功能）", label)
	}
	if g := mapGet(cc, "GlobalDeviceLimitConfig"); g != nil {
		if e := mapGet(g, "Enable"); e != nil && strings.EqualFold(e.Value, "true") {
			m.report.warn("%s: GlobalDeviceLimitConfig(Redis) 已移除，跨节点设备数改由 Xboard 在线设备统计实现，无需 Redis", label)
		}
		mapDelete(cc, "GlobalDeviceLimitConfig")
		m.report.change("%s: 删除 GlobalDeviceLimitConfig", label)
	}
	if c := mapGet(cc, "CertConfig"); c != nil {
		if strings.EqualFold(scalar(c, "CertMode"), certcfg.ModeFile) {
			for _, k := range []string{"CertFile", "KeyFile"} {
				if p := m.origin[scalar(c, k)]; p != "" {
					if _, err := os.Stat(p); err != nil {
						m.report.warn("%s: CertConfig.%s 指向的 %s 不存在", label, k, p)
					}
				}
			}
		}
		m.planACMECert(label, c)
	}
	return true
}

// nodeType reproduces the node_type XrayR sent to the panel.
func nodeType(t string, enableVless bool) string {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "v2ray":
		if enableVless {
			return "vless"
		}
		return "vmess"
	case "shadowsocks-plugin":
		return "shadowsocks"
	default:
		return strings.ToLower(strings.TrimSpace(t))
	}
}

// planACMECert copies a certificate issued by XrayR so W1nCray does not have
// to request a new one (Let's Encrypt rate limits).
func (m *migration) planACMECert(label string, c *yaml.Node) {
	mode := strings.ToLower(scalar(c, "CertMode"))
	domain := scalar(c, "CertDomain")
	if (mode != certcfg.ModeDNS && mode != certcfg.ModeHTTP && mode != certcfg.ModeTLS) || domain == "" {
		return
	}
	if mode == certcfg.ModeDNS && !certcfg.DNSProviderSupported(scalar(c, "Provider")) {
		m.report.warn("%s: 证书使用 DNS 供应商 %q，当前程序是 %s 版，不包含它；请安装完整版（W1nCray update --full），否则 W1nCray 无法自动续期该证书", label, scalar(c, "Provider"), certcfg.BuildFlavor)
	}
	cfg := &certcfg.Config{CertDomain: domain, CertFile: scalar(c, "CertFile"), KeyFile: scalar(c, "KeyFile")}
	dstCert, dstKey := certcfg.TargetPaths(filepath.Join(m.toDir, "cert"), cfg)
	name := strings.ReplaceAll(domain, "*", "_")
	dirs := append([]string{m.fromDir}, m.opts.SearchDirs...)
	for _, d := range dirs {
		srcCert := filepath.Join(d, "cert", "certificates", name+".crt")
		srcKey := filepath.Join(d, "cert", "certificates", name+".key")
		if certcfg.Valid(srcCert, srcKey, domain) {
			m.plan(srcCert, filepath.FromSlash(dstCert))
			m.plan(srcKey, filepath.FromSlash(dstKey))
			m.report.change("%s: 沿用 XrayR 已签发的 %s 证书", label, domain)
			return
		}
	}
	m.report.warn("%s: 未找到 XrayR 为 %s 签发的有效证书；仅当该节点在面板启用 TLS 时需要，届时 W1nCray 会自动申请", label, domain)
}

func (m *migration) planKnownFiles() {
	for _, f := range knownFiles {
		src := filepath.Join(m.fromDir, f)
		if _, err := os.Stat(src); err == nil {
			m.plan(src, filepath.Join(m.toDir, f))
		}
	}
	for _, f := range geoFiles {
		found := false
		for _, d := range append([]string{m.fromDir}, m.opts.SearchDirs...) {
			src := filepath.Join(d, f)
			if _, err := os.Stat(src); err == nil {
				m.plan(src, filepath.Join(m.toDir, f))
				found = true
				break
			}
		}
		if !found {
			m.report.warn("未找到 %s；面板路由使用 geosite:/geoip: 时需要它（安装脚本会自动下载）", f)
		}
	}
}

func (m *migration) execute(config []byte) error {
	for _, dst := range m.order {
		src := m.planned[dst]
		c := Copy{From: src, To: dst}
		if _, err := os.Stat(dst); err == nil && !m.opts.Force {
			c.Skipped = "目标已存在"
		} else if !m.opts.DryRun {
			if err := copyFile(src, dst); err != nil {
				return fmt.Errorf("copy %s: %w", src, err)
			}
		}
		m.report.Copies = append(m.report.Copies, c)
	}
	if m.opts.DryRun {
		return nil
	}
	if err := os.MkdirAll(m.toDir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(m.report.Config, config, 0o600)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	st, err := in.Stat()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, st.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

// ---- yaml.Node helpers --------------------------------------------------

func mapGet(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func scalar(m *yaml.Node, key string) string {
	if v := mapGet(m, key); v != nil && v.Kind == yaml.ScalarNode && v.Tag != "!!null" {
		return v.Value
	}
	return ""
}

func mapDelete(m *yaml.Node, key string) bool {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content = append(m.Content[:i], m.Content[i+2:]...)
			return true
		}
	}
	return false
}

func mapSet(m *yaml.Node, key, value, tag string) {
	if v := mapGet(m, key); v != nil {
		v.Kind, v.Tag, v.Value, v.Content = yaml.ScalarNode, tag, value, nil
		return
	}
	m.Content = append(m.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		&yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: value})
}
