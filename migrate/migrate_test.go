package migrate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/common/cert"
	"github.com/W1nCwC/W1nCray/config"
)

// A typical XrayR config for a V2board/Xboard panel. {{FROM}} is the XrayR
// directory (/etc/XrayR in a real install).
const xrayrConfig = `Log:
  Level: warning # Log level: none, error, warning, info, debug
  AccessPath: # {{FROM}}/access.Log
  ErrorPath: {{FROM}}/error.log
DnsConfigPath: {{FROM}}/dns.json
RouteConfigPath: {{FROM}}/route.json
InboundConfigPath: # {{FROM}}/custom_inbound.json
OutboundConfigPath: {{FROM}}/custom_outbound.json
ConnectionConfig:
  Handshake: 4
  ConnIdle: 30
  UplinkOnly: 2
  DownlinkOnly: 4
  BufferSize: 64
Nodes:
  - PanelType: "NewV2board" # vless reality node
    ApiConfig:
      ApiHost: "https://panel.example.com"
      ApiKey: "key123"
      NodeID: 11
      NodeType: V2ray
      Timeout: 30
      EnableVless: true
      VlessFlow: "xtls-rprx-vision"
      SpeedLimit: 0
      DeviceLimit: 0
      RuleListPath: {{FROM}}/rulelist
    ControllerConfig:
      ListenIP: 0.0.0.0
      SendIP: 0.0.0.0
      UpdatePeriodic: 60
      DisableIVCheck: false
      GlobalDeviceLimitConfig:
        Enable: true
        RedisAddr: 127.0.0.1:6379
      DisableLocalREALITYConfig: true
      EnableREALITY: true
      REALITYConfigs:
        Show: true
      CertConfig:
        CertMode: none
  - PanelType: "SSpanel"
    ApiConfig:
      ApiHost: "https://sspanel.example.com"
      ApiKey: "x"
      NodeID: 3
      NodeType: Shadowsocks
  - PanelType: "V2board"
    ApiConfig:
      ApiHost: "https://panel.example.com"
      ApiKey: "key123"
      NodeID: 12
      NodeType: Trojan
    ControllerConfig:
      CertConfig:
        CertMode: dns # issued by XrayR, must be reused
        CertDomain: "node.example.com"
        CertFile: {{FROM}}/cert/node.example.com.cert
        KeyFile: {{FROM}}/cert/node.example.com.key
        Provider: alidns
        Email: test@me.com
        DNSEnv:
          ALICLOUD_ACCESS_KEY: aaa
  - PanelType: "NewV2board"
    ApiConfig:
      ApiHost: "https://panel.example.com"
      ApiKey: "key123"
      NodeID: 13
      NodeType: Shadowsocks
    ControllerConfig:
      CertConfig:
        CertMode: file
        CertFile: {{FROM}}/cert/file.crt
        KeyFile: {{FROM}}/cert/file.key
`

// A route.json that works with both kernels (XrayR's default one does not).
const validRoute = `{
  "domainStrategy": "IPOnDemand",
  "rules": [
    {"type": "field", "outboundTag": "block", "protocol": ["bittorrent"]},
    {"type": "field", "outboundTag": "IPv4_out", "network": "udp,tcp"}
  ]
}`

func setupXrayR(t *testing.T) (from, to string) {
	t.Helper()
	root := t.TempDir()
	from = filepath.ToSlash(filepath.Join(root, "XrayR"))
	to = filepath.ToSlash(filepath.Join(root, "W1nCray"))
	write := func(rel string, data []byte) {
		p := filepath.Join(from, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("config.yml", []byte(strings.ReplaceAll(xrayrConfig, "{{FROM}}", from)))
	sample := filepath.Join("testdata", "xrayr-v0.9.4")
	for _, f := range []string{"dns.json", "custom_outbound.json", "custom_inbound.json", "rulelist"} {
		b, err := os.ReadFile(filepath.Join(sample, f))
		if err != nil {
			t.Fatal(err)
		}
		write(f, b)
	}
	write("route.json", []byte(validRoute))
	write("geoip.dat", []byte("not a real geo file"))
	write("geosite.dat", []byte("not a real geo file"))

	// Certificate XrayR obtained through lego: <dir>/cert/certificates/<domain>.crt
	c, k, err := cert.SelfSigned("node.example.com", 90*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	write("cert/certificates/node.example.com.crt", c)
	write("cert/certificates/node.example.com.key", k)
	fc, fk, _ := cert.SelfSigned("file.example.com", 90*24*time.Hour)
	write("cert/file.crt", fc)
	write("cert/file.key", fk)
	return from, to
}

func hashTree(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, _ := os.ReadFile(p)
		s := sha256.Sum256(b)
		out[p] = hex.EncodeToString(s[:])
		return nil
	})
	return out
}

func TestMigrate(t *testing.T) {
	from, to := setupXrayR(t)
	before := hashTree(t, from)

	r, err := Run(Options{From: from, To: to, SearchDirs: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Log("\n" + r.String())

	// The XrayR directory is untouched.
	after := hashTree(t, from)
	if len(before) != len(after) {
		t.Fatalf("source tree changed: %d -> %d files", len(before), len(after))
	}
	for p, h := range before {
		if after[p] != h {
			t.Fatalf("source file modified: %s", p)
		}
	}

	out, err := os.ReadFile(filepath.Join(to, "config.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	// The first line is the migration banner, which records the source path on
	// purpose. Without this exemption the check below only ever worked on
	// Windows, where the path has backslashes and from+"/" never matched.
	if i := strings.IndexByte(text, '\n'); i >= 0 && strings.HasPrefix(text, "# Migrated from XrayR") {
		text = text[i+1:]
	}
	for _, gone := range []string{"EnableVless", "VlessFlow", "DisableIVCheck", "GlobalDeviceLimitConfig", "DisableLocalREALITYConfig", "SSpanel", from + "/"} {
		if strings.Contains(text, gone) {
			t.Errorf("migrated config still contains %q", gone)
		}
	}
	for _, kept := range []string{"# Log level: none, error, warning, info, debug", "# vless reality node", "# issued by XrayR, must be reused", "# " + to + "/access.Log"} {
		if !strings.Contains(text, kept) {
			t.Errorf("comment lost: %q", kept)
		}
	}

	cfg, err := config.Load(filepath.Join(to, "config.yml"))
	if err != nil {
		t.Fatalf("migrated config does not load: %v", err)
	}
	if len(cfg.NodesConfig) != 3 {
		t.Fatalf("%d nodes, want 3 (SSpanel removed)", len(cfg.NodesConfig))
	}
	n0, n1, n2 := cfg.NodesConfig[0], cfg.NodesConfig[1], cfg.NodesConfig[2]
	if n0.PanelType != "Xboard" || n0.ApiConfig.NodeType != "vless" || n1.ApiConfig.NodeType != "trojan" || n2.ApiConfig.NodeType != "shadowsocks" {
		t.Fatalf("panel/node types: %s %s %s %s", n0.PanelType, n0.ApiConfig.NodeType, n1.ApiConfig.NodeType, n2.ApiConfig.NodeType)
	}
	if n0.ControllerConfig.EnableREALITY {
		t.Fatal("DisableLocalREALITYConfig: true must become EnableREALITY: false")
	}
	if cfg.DnsConfigPath != to+"/dns.json" || cfg.RouteConfigPath != to+"/route.json" || cfg.OutboundConfigPath != to+"/custom_outbound.json" || cfg.LogConfig.ErrorPath != to+"/error.log" {
		t.Fatalf("paths not rewritten: %+v %+v", cfg, cfg.LogConfig)
	}
	if n0.ApiConfig.RuleListPath != to+"/rulelist" {
		t.Fatalf("rule list path %s", n0.ApiConfig.RuleListPath)
	}
	if cfg.InboundConfigPath != "" {
		t.Fatal("commented-out path must stay unset")
	}

	for _, f := range []string{"dns.json", "route.json", "custom_outbound.json", "custom_inbound.json", "rulelist", "geoip.dat", "geosite.dat", "cert/file.crt", "cert/file.key"} {
		if _, err := os.Stat(filepath.Join(to, f)); err != nil {
			t.Errorf("not copied: %s", f)
		}
	}

	// The ACME certificate lands where W1nCray's cert manager looks for it,
	// so it is reused instead of requesting a new one.
	cc := n1.ControllerConfig.CertConfig
	cf, kf := cert.TargetPaths(filepath.Join(to, "cert"), cc)
	if !cert.Valid(cf, kf, "node.example.com") {
		t.Fatalf("XrayR ACME certificate not reusable at %s", cf)
	}
	m := cert.NewManager(filepath.Join(to, "cert"))
	if _, _, renewed, err := m.Ensure(cc); err != nil || renewed {
		t.Fatalf("cert manager would not reuse the certificate: renewed=%v err=%v", renewed, err)
	}

	joined := strings.Join(r.Warnings, "\n")
	for _, w := range []string{"SSpanel", "GlobalDeviceLimitConfig"} {
		if !strings.Contains(joined, w) {
			t.Errorf("missing warning about %s", w)
		}
	}

	// The migrated JSON files are syntactically valid. The Xray semantic check
	// moved to the kernel program (`W1nCray-xray check`): the agent no longer
	// links Xray-core, so this test only asserts what it can still own.
	for _, p := range []string{cfg.DnsConfigPath, cfg.RouteConfigPath, cfg.OutboundConfigPath} {
		if p == "" {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("migrated file %s: %v", p, err)
		}
		var v any
		if err := json.Unmarshal(b, &v); err != nil {
			t.Fatalf("migrated file %s is not valid JSON: %v", p, err)
		}
	}
}

func TestMigrateDryRunAndExisting(t *testing.T) {
	from, to := setupXrayR(t)
	r, err := Run(Options{From: from, To: to, DryRun: true, SearchDirs: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Copies) == 0 {
		t.Fatal("dry-run must still plan copies")
	}
	if _, err := os.Stat(to); !os.IsNotExist(err) {
		t.Fatal("dry-run wrote files")
	}

	if _, err := Run(Options{From: from, To: to, SearchDirs: []string{}}); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(Options{From: from, To: to, SearchDirs: []string{}}); err == nil {
		t.Fatal("existing target must be refused without --force")
	}
	if _, err := Run(Options{From: from, To: to, Force: true, SearchDirs: []string{}}); err != nil {
		t.Fatalf("--force: %v", err)
	}
	if _, err := Run(Options{From: from, To: from, SearchDirs: []string{}}); err == nil {
		t.Fatal("same source and target must be refused")
	}
}

// The XrayR v0.9.4 example config only has an SSpanel node.
func TestMigrateXrayRExampleOnlySSpanel(t *testing.T) {
	dir := t.TempDir()
	b, err := os.ReadFile(filepath.Join("testdata", "xrayr-v0.9.4", "config.yml.example"))
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "config.yml"), b, 0o644)
	_, err = Run(Options{From: dir, To: filepath.Join(dir, "out"), SearchDirs: []string{}})
	if err == nil || !strings.Contains(err.Error(), "supported panel") {
		t.Fatalf("err = %v", err)
	}

	// The same file with a V2board panel migrates and loads.
	os.WriteFile(filepath.Join(dir, "config.yml"), []byte(strings.Replace(string(b), `PanelType: "SSpanel"`, `PanelType: "NewV2board"`, 1)), 0o644)
	r, err := Run(Options{From: dir, To: filepath.Join(dir, "out"), SearchDirs: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(r.Config); err != nil {
		t.Fatalf("migrated example does not load: %v", err)
	}
}

// TestCheckNamesBrokenFile moved to xraynode (TestCoreValidatorNamesTheBrokenRouteRule):
// the Xray file check is the kernel program's, and the agent no longer links
// Xray-core.
