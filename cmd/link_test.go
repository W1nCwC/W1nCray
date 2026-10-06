package cmd

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/node"
	"github.com/W1nCwC/W1nCray/panel"
)

// The fixture is a sanitized but real-shaped v0.3 config: three nodes of the
// same panel (vmess with PROXY protocol + a DNS certificate, shadowsocks
// without a certificate, vless with local DNS/REALITY), one node of another
// panel and one node with a local SpeedLimit. Credentials are placeholders.
const linkFixturePrelude = `# W1nCray config (fixture) — the top comment must survive
Log:                       # logging stays untouched
  Level: info
  AccessPath: /var/log/W1nCray/access.log

ConnectionConfig:
  Handshake: 4
  ConnIdle: 30

Nodes:
`

const linkEntry173 = `  # 173: vmess, PROXY protocol and a DNS certificate (Cloudflare credentials stay local)
  - PanelType: "Xboard"
    ApiConfig:
      ApiHost: "https://panel.example.com"
      ApiKey: "fixture-api-key"
      NodeID: 173
      NodeType: V2ray
    ControllerConfig:
      ListenIP: 0.0.0.0
      EnableProxyProtocol: true
      CertConfig:
        CertMode: dns
        CertDomain: node173.example.com
        Provider: cloudflare
        DNSEnv:
          CLOUDFLARE_EMAIL: a@b.c
          CLOUDFLARE_API_KEY: fixture-secret-value
`

const linkEntry119 = `  # 119: shadowsocks, no certificate
  - PanelType: "Xboard"
    ApiConfig:
      ApiHost: https://panel.example.com/
      ApiKey: "fixture-api-key"
      NodeID: 119
      NodeType: Shadowsocks
    ControllerConfig:
      ListenIP: 0.0.0.0
      CertConfig:
        CertMode: none
`

const linkEntry138 = `  # 138: vless with local DNS and REALITY
  - PanelType: "Xboard"
    ApiConfig:
      ApiHost: https://panel.example.com
      ApiKey: "fixture-api-key"
      NodeID: 138
      NodeType: Vless
    ControllerConfig:
      EnableDNS: true
      DNSType: UseIPv4
      REALITYConfigs:
        Show: true
`

const linkEntry200 = `  # 200: another panel, stays static
  - PanelType: "Xboard"
    ApiConfig:
      ApiHost: https://other.example.com
      ApiKey: "fixture-api-key"
      NodeID: 200
      NodeType: V2ray
    ControllerConfig:
      ListenIP: 127.0.0.1
`

const linkEntry201 = `  # 201: same panel but a local SpeedLimit, stays static
  - PanelType: "Xboard"
    ApiConfig:
      ApiHost: https://panel.example.com
      ApiKey: "fixture-api-key"
      NodeID: 201
      NodeType: V2ray
      SpeedLimit: 100
    ControllerConfig:
      ListenIP: 0.0.0.0
`

const linkFixture = linkFixturePrelude + linkEntry173 + "\n" + linkEntry119 + "\n" + linkEntry138 + "\n" + linkEntry200 + "\n" + linkEntry201

const (
	linkTestToken = "fixture-machine-token"
	linkSecret    = "fixture-secret-value"
)

func linkTestOpts() linkOptions {
	return linkOptions{
		Panel:     "https://panel.example.com",
		Machine:   7,
		Token:     linkTestToken,
		PortRange: "20000-40000",
	}
}

func writeLinkFixture(t *testing.T, content string) (dir, cfgPath string) {
	t.Helper()
	dir = t.TempDir()
	cfgPath = filepath.Join(dir, "config.yml")
	if err := os.WriteFile(cfgPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, cfgPath
}

// commentEntry returns the entry text (the standalone leading comment is not
// part of the entry) with every line commented out, as `link` writes it.
func commentEntry(t *testing.T, entry string) string {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(entry, "\n"), "\n")
	if len(lines) < 2 {
		t.Fatalf("fixture entry too short: %q", entry)
	}
	lines = lines[1:] // drop the leading comment, which the parser leaves in place
	for i := range lines {
		lines[i] = "#" + lines[i]
	}
	return strings.Join(lines, "\n")
}

func TestLinkConvertsMatchingNodesAndPreservesControllerConfig(t *testing.T) {
	dir, cfgPath := writeLinkFixture(t, linkFixture)

	before, err := panel.LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("the fixture must be valid: %v", err)
	}
	want := map[int]*node.Config{}
	for _, n := range before.NodesConfig {
		switch n.ApiConfig.NodeID {
		case 173, 119, 138:
			want[n.ApiConfig.NodeID] = n.ControllerConfig
		}
	}
	if len(want) != 3 {
		t.Fatalf("fixture decoded %d of the three nodes to convert", len(want))
	}

	var out bytes.Buffer
	if err := runLink(cfgPath, linkTestOpts(), &out); err != nil {
		t.Fatalf("link failed: %v\n%s", err, out.String())
	}

	after, err := panel.LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("the converted config must load: %v\n%s", err, out.String())
	}
	if after.Agent == nil || !after.Agent.Enabled {
		t.Fatal("Agent.Enabled is not set")
	}
	if after.Agent.StateDir != filepath.Join(dir, "state") {
		t.Errorf("StateDir = %q, want %q", after.Agent.StateDir, filepath.Join(dir, "state"))
	}
	if got := after.Agent.Policy.AllowListen; !reflect.DeepEqual(got, []string{"0.0.0.0"}) {
		t.Errorf("AllowListen = %v", got)
	}
	if got := after.Agent.Policy.PortRange; !reflect.DeepEqual(got, []int{20000, 40000}) {
		t.Errorf("PortRange = %v", got)
	}
	if len(after.Agent.Policy.AllowEngines) != 0 {
		t.Errorf("AllowEngines must stay empty (the panel installs what it needs), got %v", after.Agent.Policy.AllowEngines)
	}
	pc := after.Agent.Panel
	if pc == nil || !pc.Enabled || !pc.MachineNodes {
		t.Fatalf("Panel = %+v, want enabled machine mode", pc)
	}
	if pc.URL != "https://panel.example.com" {
		t.Errorf("URL = %q", pc.URL)
	}
	if pc.MachineID != 7 {
		t.Errorf("MachineID = %d", pc.MachineID)
	}
	if pc.TokenFile != filepath.Join(dir, "agent.token") {
		t.Errorf("TokenFile = %q", pc.TokenFile)
	}
	if pc.Token != "" {
		t.Error("the token must never be written into the config")
	}

	// The three matching nodes are now machine nodes with a verbatim
	// ControllerConfig; the other two stay static.
	if len(after.NodesConfig) != 2 {
		t.Fatalf("static nodes = %d, want 2", len(after.NodesConfig))
	}
	static := map[int]bool{}
	for _, n := range after.NodesConfig {
		static[n.ApiConfig.NodeID] = true
	}
	if !static[200] || !static[201] {
		t.Errorf("static nodes = %v, want 200 and 201", static)
	}
	for id, w := range want {
		got, ok := pc.NodeControllers[id]
		if !ok {
			t.Errorf("NodeControllers[%d] is missing", id)
			continue
		}
		if !reflect.DeepEqual(got, w) {
			t.Errorf("NodeControllers[%d] = %+v, want the original ControllerConfig %+v", id, got, w)
		}
	}
	if len(pc.NodeControllers) != 3 {
		t.Errorf("NodeControllers has %d entries, want 3", len(pc.NodeControllers))
	}
}

func TestLinkCommentsConvertedEntriesAndKeepsTheRest(t *testing.T) {
	_, cfgPath := writeLinkFixture(t, linkFixture)
	orig, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runLink(cfgPath, linkTestOpts(), &out); err != nil {
		t.Fatalf("link failed: %v\n%s", err, out.String())
	}
	got, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	content := string(got)

	today := time.Now().Format("2006-01-02")
	for _, id := range []int{173, 119, 138} {
		want := fmt.Sprintf("#LINKED-%s node %d now runs in machine mode (Agent.Panel, machine 7); original static entry kept below for rollback", today, id)
		if !strings.Contains(content, want) {
			t.Errorf("missing rollback marker %q", want)
		}
	}
	for _, entry := range []string{linkEntry173, linkEntry119, linkEntry138} {
		commented := commentEntry(t, entry)
		if !strings.Contains(content, commented) {
			t.Errorf("converted entry is not kept, commented out:\n%s", commented)
		}
	}
	// Nodes of another panel / with a local override stay untouched, comments
	// and all.
	for _, entry := range []string{linkEntry200, linkEntry201} {
		if !strings.Contains(content, entry) {
			t.Errorf("untouched entry changed:\n%s", entry)
		}
	}
	// Every original comment survives (converted blocks gain one leading '#').
	for _, line := range strings.Split(string(orig), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if !strings.Contains(content, line) && !strings.Contains(content, "#"+line) {
			t.Errorf("comment %q disappeared", line)
		}
	}
}

func TestLinkLeavesUnrelatedTopLevelKeysUnchanged(t *testing.T) {
	_, cfgPath := writeLinkFixture(t, linkFixture)
	before, err := panel.LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := runLink(cfgPath, linkTestOpts(), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	after, err := panel.LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before.LogConfig, after.LogConfig) {
		t.Errorf("Log changed: %+v -> %+v", before.LogConfig, after.LogConfig)
	}
	if !reflect.DeepEqual(before.ConnectionConfig, after.ConnectionConfig) {
		t.Errorf("ConnectionConfig changed: %+v -> %+v", before.ConnectionConfig, after.ConnectionConfig)
	}
	if before.DnsConfigPath != after.DnsConfigPath || before.RouteConfigPath != after.RouteConfigPath ||
		before.InboundConfigPath != after.InboundConfigPath || before.OutboundConfigPath != after.OutboundConfigPath ||
		before.CertDir != after.CertDir {
		t.Error("a top-level path key changed")
	}
}

func TestLinkSkipsNodesOfAnotherPanel(t *testing.T) {
	_, cfgPath := writeLinkFixture(t, linkFixture)
	var out bytes.Buffer
	if err := runLink(cfgPath, linkTestOpts(), &out); err != nil {
		t.Fatal(err)
	}
	after, err := panel.LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, n := range after.NodesConfig {
		if n.ApiConfig.NodeID == 200 {
			found = true
		}
	}
	if !found {
		t.Error("node 200 (another panel) was converted")
	}
	if !strings.Contains(out.String(), "节点 200") {
		t.Errorf("the report does not list node 200 as skipped:\n%s", out.String())
	}
}

func TestLinkSkipsNodesWithAPIConfigOverrides(t *testing.T) {
	_, cfgPath := writeLinkFixture(t, linkFixture)
	var out bytes.Buffer
	if err := runLink(cfgPath, linkTestOpts(), &out); err != nil {
		t.Fatal(err)
	}
	after, err := panel.LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range after.NodesConfig {
		if n.ApiConfig.NodeID == 201 {
			if _, ok := after.Agent.Panel.NodeControllers[201]; ok {
				t.Error("node 201 with SpeedLimit must not get a machine override")
			}
			if !strings.Contains(out.String(), "SpeedLimit") {
				t.Errorf("the report does not name the SpeedLimit override:\n%s", out.String())
			}
			return
		}
	}
	t.Error("node 201 (SpeedLimit) was converted")
}

func TestLinkIgnoreAPIConfigOverrides(t *testing.T) {
	_, cfgPath := writeLinkFixture(t, linkFixture)
	opts := linkTestOpts()
	opts.IgnoreAPIOverrides = true
	if err := runLink(cfgPath, opts, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	after, err := panel.LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := after.Agent.Panel.NodeControllers[201]; !ok {
		t.Error("node 201 was not converted with --ignore-api-overrides")
	}
}

func TestLinkRefusesAnAlreadyLinkedPanel(t *testing.T) {
	linked := linkFixture + `
Agent:
  Enabled: true
  Panel:
    Enabled: true
    URL: https://panel.example.com
    MachineID: 7
    TokenFile: agent.token
`
	_, cfgPath := writeLinkFixture(t, linked)
	orig, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	err = runLink(cfgPath, linkTestOpts(), &bytes.Buffer{})
	if err == nil {
		t.Fatal("link overwrote an already linked config")
	}
	if !strings.Contains(err.Error(), "拒绝覆盖") {
		t.Errorf("error %q does not refuse to overwrite", err)
	}
	got, _ := os.ReadFile(cfgPath)
	if !bytes.Equal(orig, got) {
		t.Error("the config changed although the command refused to run")
	}
}

func TestLinkRefusesAnExistingAgentWithoutPanel(t *testing.T) {
	linked := linkFixture + `
Agent:
  Enabled: true
  DesiredPath: /etc/W1nCray/desired.json
`
	_, cfgPath := writeLinkFixture(t, linked)
	orig, _ := os.ReadFile(cfgPath)
	err := runLink(cfgPath, linkTestOpts(), &bytes.Buffer{})
	if err == nil {
		t.Fatal("link guessed where to merge the Panel section")
	}
	if !strings.Contains(err.Error(), "手工") {
		t.Errorf("error %q does not ask for a manual merge", err)
	}
	got, _ := os.ReadFile(cfgPath)
	if !bytes.Equal(orig, got) {
		t.Error("the config changed although the command refused to run")
	}
}

func TestLinkIsIdempotentAndRefusesToRunTwice(t *testing.T) {
	_, cfgPath := writeLinkFixture(t, linkFixture)
	if err := runLink(cfgPath, linkTestOpts(), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	first, _ := os.ReadFile(cfgPath)
	err := runLink(cfgPath, linkTestOpts(), &bytes.Buffer{})
	if err == nil {
		t.Fatal("a second link run succeeded")
	}
	if !strings.Contains(err.Error(), "#LINKED-") {
		t.Errorf("error %q does not explain that the config was already converted", err)
	}
	second, _ := os.ReadFile(cfgPath)
	if !bytes.Equal(first, second) {
		t.Error("the second run changed the config")
	}
}

// With every node converted the Nodes sequence holds only comments, so the
// "already linked" refusal must not be hidden behind "no Nodes entries".
func TestLinkRefusesToRunTwiceWhenNoStaticNodeRemains(t *testing.T) {
	fixture := linkFixturePrelude + linkEntry173 + "\n" + linkEntry119
	_, cfgPath := writeLinkFixture(t, fixture)
	if err := runLink(cfgPath, linkTestOpts(), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	first, _ := os.ReadFile(cfgPath)
	err := runLink(cfgPath, linkTestOpts(), &bytes.Buffer{})
	if err == nil {
		t.Fatal("a second link run succeeded")
	}
	if !strings.Contains(err.Error(), "#LINKED-") {
		t.Errorf("error %q does not explain that the config was already converted", err)
	}
	second, _ := os.ReadFile(cfgPath)
	if !bytes.Equal(first, second) {
		t.Error("the second run changed the config")
	}
}

func TestLinkDryRunWritesNothing(t *testing.T) {
	dir, cfgPath := writeLinkFixture(t, linkFixture)
	orig, _ := os.ReadFile(cfgPath)
	opts := linkTestOpts()
	opts.DryRun = true
	var out bytes.Buffer
	if err := runLink(cfgPath, opts, &out); err != nil {
		t.Fatalf("dry-run failed: %v", err)
	}
	got, _ := os.ReadFile(cfgPath)
	if !bytes.Equal(orig, got) {
		t.Error("dry-run changed the config")
	}
	if _, err := os.Stat(filepath.Join(dir, "agent.token")); !os.IsNotExist(err) {
		t.Error("dry-run wrote the token file")
	}
	if b, _ := filepath.Glob(cfgPath + ".bak-link-*"); len(b) != 0 {
		t.Errorf("dry-run created a backup: %v", b)
	}
	s := out.String()
	for _, want := range []string{"dry-run", "119, 138, 173", "节点 201", "agent.token"} {
		if !strings.Contains(s, want) {
			t.Errorf("dry-run report does not mention %q:\n%s", want, s)
		}
	}
}

func TestLinkWritesTokenFileAndNeverLeaksIt(t *testing.T) {
	dir, cfgPath := writeLinkFixture(t, linkFixture)
	var out bytes.Buffer
	if err := runLink(cfgPath, linkTestOpts(), &out); err != nil {
		t.Fatalf("link failed: %v", err)
	}

	tokenPath := filepath.Join(dir, "agent.token")
	fi, err := os.Stat(tokenPath)
	if err != nil {
		t.Fatalf("token file: %v", err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("token file mode = %04o, want 0600", fi.Mode().Perm())
	}
	b, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != linkTestToken {
		t.Errorf("token file content is not the token (length %d)", len(b))
	}
	if strings.HasSuffix(string(b), "\n") {
		t.Error("token file must not end with a newline")
	}

	// The token must not appear on stdout/stderr or in the config. The
	// Cloudflare credential may only live in the config, where it already was.
	cfgText, _ := os.ReadFile(cfgPath)
	for _, where := range []struct {
		name string
		text string
	}{
		{"stdout", out.String()},
		{"config", string(cfgText)},
	} {
		if strings.Contains(where.text, linkTestToken) {
			t.Errorf("the token leaked into %s", where.name)
		}
	}
	if strings.Contains(out.String(), linkSecret) {
		t.Error("the Cloudflare credential leaked to stdout")
	}
	// The credential is allowed only where it already was: the original
	// ControllerConfig. It now exists twice (the rollback block and the
	// NodeControllers copy) and nowhere else.
	if n := strings.Count(string(cfgText), linkSecret); n != 2 {
		t.Errorf("the credential appears %d times in the config, want 2 (rollback block + NodeControllers)", n)
	}
	if strings.Contains(string(b), linkSecret) {
		t.Error("the Cloudflare credential leaked into the token file")
	}
}

func TestLinkReadsTokenFromFile(t *testing.T) {
	dir, cfgPath := writeLinkFixture(t, linkFixture)
	tokenFile := filepath.Join(dir, "token-source")
	// Surrounding whitespace/newline is ignored, like the panel client does.
	if err := os.WriteFile(tokenFile, []byte("  from-a-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := linkTestOpts()
	opts.Token = ""
	opts.TokenFile = tokenFile
	var out bytes.Buffer
	if err := runLink(cfgPath, opts, &out); err != nil {
		t.Fatalf("link failed: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "agent.token"))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "from-a-file" {
		t.Errorf("agent.token = %q, want the trimmed token from --token-file", b)
	}
	if strings.Contains(out.String(), "from-a-file") {
		t.Error("the token leaked to stdout")
	}
}

func TestLinkKeepsAnExistingIdenticalTokenFile(t *testing.T) {
	dir, cfgPath := writeLinkFixture(t, linkFixture)
	tokenPath := filepath.Join(dir, "agent.token")
	if err := os.WriteFile(tokenPath, []byte(linkTestToken), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(tokenPath, old, old); err != nil {
		t.Fatal(err)
	}
	if err := runLink(cfgPath, linkTestOpts(), &bytes.Buffer{}); err != nil {
		t.Fatalf("link failed: %v", err)
	}
	after, err := os.Stat(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if after.ModTime().After(old.Add(time.Minute)) {
		t.Error("an already correct token file was rewritten")
	}
	b, _ := os.ReadFile(tokenPath)
	if string(b) != linkTestToken {
		t.Errorf("token file = %q", b)
	}
}

func TestLinkBacksUpTheOriginalConfig(t *testing.T) {
	dir, cfgPath := writeLinkFixture(t, linkFixture)
	orig, _ := os.ReadFile(cfgPath)
	if err := runLink(cfgPath, linkTestOpts(), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	backups, err := filepath.Glob(cfgPath + ".bak-link-*")
	if err != nil || len(backups) != 1 {
		t.Fatalf("backups = %v (%v), want exactly one", backups, err)
	}
	b, err := os.ReadFile(backups[0])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, orig) {
		t.Error("the backup does not equal the original config")
	}
	if fi, err := os.Stat(backups[0]); err == nil && runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("backup mode = %04o, want 0600", fi.Mode().Perm())
	}
	if filepath.Dir(backups[0]) != dir {
		t.Errorf("backup written to %s, want the config directory %s", filepath.Dir(backups[0]), dir)
	}
}

// TestLinkKeepsEveryFileOnValidationFailure: a problem the conversion itself
// introduces still aborts with zero changes. The offline `W1nCray check` does
// not look at a machine node's ControllerConfig (it only matters once the node
// runs), so an unusable certificate mode is exactly the kind of new problem
// link has to catch: the config, the backup and the token file must all be
// left untouched, and the token must not leak into the report.
func TestLinkKeepsEveryFileOnValidationFailure(t *testing.T) {
	dir, cfgPath := writeLinkFixture(t, linkFixture)
	// node 173 is converted and carries a certificate mode machine mode cannot
	// use; the original config passes the offline check, the conversion does
	// not.
	broken := strings.Replace(linkFixture, "CertMode: dns", "CertMode: bogus-mode", 1)
	if err := os.WriteFile(cfgPath, []byte(broken), 0o600); err != nil {
		t.Fatal(err)
	}
	orig, _ := os.ReadFile(cfgPath)

	var out bytes.Buffer
	err := runLink(cfgPath, linkTestOpts(), &out)
	if err == nil {
		t.Fatalf("link succeeded although the generated config introduces a new problem:\n%s", out.String())
	}
	if strings.Contains(err.Error(), linkTestToken) || strings.Contains(out.String(), linkTestToken) {
		t.Error("the token leaked into the validation error")
	}
	if !strings.Contains(out.String(), "新增失败项") || !strings.Contains(out.String(), "bogus-mode") {
		t.Errorf("the report does not name the new failure item:\n%s", out.String())
	}
	got, _ := os.ReadFile(cfgPath)
	if !bytes.Equal(orig, got) {
		t.Error("the config changed although validation failed")
	}
	if b, _ := filepath.Glob(cfgPath + ".bak-link-*"); len(b) != 0 {
		t.Errorf("a backup was created although validation failed: %v", b)
	}
	if _, err := os.Stat(filepath.Join(dir, "agent.token")); !os.IsNotExist(err) {
		t.Error("the token file was left behind although validation failed")
	}
}

// TestLinkProceedsOnAPreExistingProblem: a problem the original config already
// had (here a route.json that is not valid JSON) must not block the
// conversion; it is reported as a warning and the conversion is written.
func TestLinkProceedsOnAPreExistingProblem(t *testing.T) {
	dir, cfgPath := writeLinkFixture(t, linkFixture)
	routePath := filepath.Join(dir, "route.json")
	if err := os.WriteFile(routePath, []byte("{ this is not valid json"), 0o600); err != nil {
		t.Fatal(err)
	}
	broken := strings.Replace(linkFixture, "ConnectionConfig:",
		"RouteConfigPath: "+filepath.ToSlash(routePath)+"\nConnectionConfig:", 1)
	if err := os.WriteFile(cfgPath, []byte(broken), 0o600); err != nil {
		t.Fatal(err)
	}
	orig, _ := os.ReadFile(cfgPath)

	var out bytes.Buffer
	if err := runLink(cfgPath, linkTestOpts(), &out); err != nil {
		t.Fatalf("link blocked on a problem the original config already had: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "转换前就有以下问题") {
		t.Errorf("the report does not warn about the pre-existing problem:\n%s", out.String())
	}
	if _, err := panel.LoadConfig(cfgPath); err != nil {
		t.Fatalf("the converted config must load: %v", err)
	}
	got, _ := os.ReadFile(cfgPath)
	if bytes.Equal(orig, got) {
		t.Error("the config was not converted")
	}
	if b, _ := filepath.Glob(cfgPath + ".bak-link-*"); len(b) != 1 {
		t.Errorf("backups = %v, want exactly one", b)
	}
}

func TestLinkAllowHTTP(t *testing.T) {
	// The matching nodes speak plain http to a non-loopback panel.
	fixture := strings.ReplaceAll(linkFixture, "https://panel.example.com", "http://panel.example.com")
	_, cfgPath := writeLinkFixture(t, fixture)
	// Refused without --allow-http...
	opts := linkTestOpts()
	opts.Panel = "http://panel.example.com"
	if err := runLink(cfgPath, opts, &bytes.Buffer{}); err == nil {
		t.Fatal("a plain http panel URL was accepted without --allow-http")
	}
	// ... and accepted with it, setting AllowInsecureHTTP.
	opts.AllowHTTP = true
	if err := runLink(cfgPath, opts, &bytes.Buffer{}); err != nil {
		t.Fatalf("link with --allow-http failed: %v", err)
	}
	after, err := panel.LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !after.Agent.Panel.AllowInsecureHTTP {
		t.Error("AllowInsecureHTTP was not written")
	}
}

func TestLinkRefusesToOverwriteADifferentTokenFile(t *testing.T) {
	dir, cfgPath := writeLinkFixture(t, linkFixture)
	tokenPath := filepath.Join(dir, "agent.token")
	if err := os.WriteFile(tokenPath, []byte("another-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	orig, _ := os.ReadFile(cfgPath)
	err := runLink(cfgPath, linkTestOpts(), &bytes.Buffer{})
	if err == nil {
		t.Fatal("link overwrote a token file with different content")
	}
	if b, _ := os.ReadFile(tokenPath); string(b) != "another-token" {
		t.Error("the existing token file changed")
	}
	if got, _ := os.ReadFile(cfgPath); !bytes.Equal(orig, got) {
		t.Error("the config changed although the token file could not be written")
	}
}

// TestLinkInlineCommentParsing pins the rule that decides where an inline value
// ends: a '#' only starts a comment at the start of the value or after
// whitespace, and never inside a quoted scalar. A value that is empty or holds
// only a comment must decode to "" so it is not mistaken for an override.
func TestLinkInlineCommentParsing(t *testing.T) {
	tests := []struct {
		line      string
		want      string
		overrides bool // the decoded value must make apiOverrideReason report an override
	}{
		{"RuleListPath:", "", false},
		{"RuleListPath: # c", "", false},
		{`RuleListPath: "" # c`, "", false},
		{"RuleListPath: /p # c", "/p", true},
		{`RuleListPath: "/p#x" # c`, "/p#x", true},
		{"RuleListPath: '/p #x'", "/p #x", true},
		{"SpeedLimit: 0 # Mbps", "0", false},
		{"SpeedLimit: 10 # x", "10", true},
		{"NodeType: vmess # t", "vmess", false},
	}
	for _, tc := range tests {
		t.Run(tc.line, func(t *testing.T) {
			key, raw, ok := lineKey(makeLine(tc.line))
			if !ok {
				t.Fatalf("lineKey(%q) did not find a key", tc.line)
			}
			got := scalarValue(raw)
			if got != tc.want {
				t.Errorf("scalarValue(%q) = %q, want %q", raw, got, tc.want)
			}
			values := map[string]string{key: got}
			get := func(name string) (string, bool) {
				v, ok := values[name]
				return v, ok
			}
			reason := apiOverrideReason(get)
			if tc.overrides && reason == "" {
				t.Errorf("apiOverrideReason(%q) found no override, want one", tc.line)
			}
			if !tc.overrides && reason != "" {
				t.Errorf("apiOverrideReason(%q) = %q, want no override", tc.line, reason)
			}
		})
	}
}

// prepareRealLinkFixture copies cmd/testdata/link_v03_real.yml into a temp
// directory and makes it self-contained: its three top-level path keys point at
// empty JSON files there, because the absolute /etc/W1nCray paths of the real
// fixture do not exist on a test machine and `link` runs the full `check`
// validation before replacing the file. Nodes, Log, ConnectionConfig, comments
// and every other line stay byte for byte the ones of the fixture.
func prepareRealLinkFixture(t *testing.T) (dir, cfgPath string, orig []byte) {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("testdata", "link_v03_real.yml"))
	if err != nil {
		t.Fatalf("read the real fixture: %v", err)
	}
	dir = t.TempDir()
	for name, body := range map[string]string{
		"route.json":           "{}",
		"custom_inbound.json":  "[]",
		"custom_outbound.json": "[]",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	text := string(src)
	for _, name := range []string{"route.json", "custom_inbound.json", "custom_outbound.json"} {
		old := "/etc/W1nCray/" + name
		if !strings.Contains(text, old) {
			t.Fatalf("the fixture no longer references %s", old)
		}
		text = strings.Replace(text, old, yamlDQ(filepath.ToSlash(filepath.Join(dir, name))), 1)
	}
	cfgPath = filepath.Join(dir, "config.yml")
	if err := os.WriteFile(cfgPath, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, cfgPath, []byte(text)
}

// TestLinkRealV03Config runs the conversion on the sanitized but real-shaped
// v0.3 config. The fixture writes the values of ApiConfig as "key: # comment"
// (empty value plus an inline comment) for RuleListPath and "key: 0 # comment"
// for SpeedLimit/DeviceLimit; before inline comments were stripped those nodes
// were skipped as "local overrides". All three nodes must convert, the backup
// must be the original file and everything else must survive unchanged.
func TestLinkRealV03Config(t *testing.T) {
	dir, cfgPath, orig := prepareRealLinkFixture(t)

	before, err := panel.LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("the prepared fixture must load: %v", err)
	}
	want := map[int]*node.Config{}
	for _, n := range before.NodesConfig {
		want[n.ApiConfig.NodeID] = n.ControllerConfig
	}
	if len(want) != 3 {
		t.Fatalf("the fixture decoded %d nodes, want 3", len(want))
	}
	for _, id := range []int{173, 119, 138} {
		if _, ok := want[id]; !ok {
			t.Fatalf("the fixture does not contain node %d", id)
		}
	}

	tokenFile := filepath.Join(dir, "token-source")
	if err := os.WriteFile(tokenFile, []byte("  fixture-machine-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := linkOptions{
		Panel:     "https://panel.example.com",
		Machine:   3,
		TokenFile: tokenFile,
		PortRange: "20000-40000",
	}
	var out bytes.Buffer
	if err := runLink(cfgPath, opts, &out); err != nil {
		t.Fatalf("link failed: %v\n%s", err, out.String())
	}
	if strings.Contains(out.String(), "跳过的节点") {
		t.Errorf("a node was skipped although the inline comments carry no value:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "119, 138, 173") {
		t.Errorf("the report does not list all three nodes:\n%s", out.String())
	}

	after, err := panel.LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("the converted config must load: %v\n%s", err, out.String())
	}
	if len(after.NodesConfig) != 0 {
		t.Errorf("%d static nodes remain, want none", len(after.NodesConfig))
	}
	pc := after.Agent.Panel
	if pc == nil || !pc.Enabled || !pc.MachineNodes {
		t.Fatalf("Panel = %+v, want enabled machine mode", pc)
	}
	if pc.MachineID != 3 {
		t.Errorf("MachineID = %d, want 3", pc.MachineID)
	}
	if len(pc.NodeControllers) != 3 {
		t.Fatalf("NodeControllers has %d entries, want 3", len(pc.NodeControllers))
	}
	for id, w := range want {
		got, ok := pc.NodeControllers[id]
		if !ok {
			t.Errorf("NodeControllers[%d] is missing", id)
			continue
		}
		if !reflect.DeepEqual(got, w) {
			t.Errorf("NodeControllers[%d] = %+v, want the original ControllerConfig %+v", id, got, w)
		}
	}
	if got := pc.NodeControllers[173]; got == nil || !got.EnableProxyProtocol {
		t.Errorf("NodeControllers[173] = %+v, want EnableProxyProtocol true", got)
	}
	if got := pc.NodeControllers[173]; got == nil || got.CertConfig == nil || len(got.CertConfig.DNSEnv) != 2 {
		t.Errorf("NodeControllers[173].CertConfig = %+v, want the two DNSEnv keys", got)
	}
	if got := pc.NodeControllers[138]; got == nil || !got.EnableDNS || got.DNSType != "UseIPv4" ||
		got.REALITYConfigs == nil || !got.REALITYConfigs.Show {
		t.Errorf("NodeControllers[138] = %+v, want EnableDNS/DNSType/REALITYConfigs", got)
	}

	backups, err := filepath.Glob(cfgPath + ".bak-link-*")
	if err != nil || len(backups) != 1 {
		t.Fatalf("backups = %v (%v), want exactly one", backups, err)
	}
	backup, err := os.ReadFile(backups[0])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(backup, orig) {
		t.Error("the backup does not equal the original config")
	}

	got, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	content := string(got)
	// Everything up to and including Nodes: is byte for byte the original
	// (Log, ConnectionConfig, the path keys and their inline comments).
	nodesAt := strings.Index(string(orig), "Nodes:")
	if nodesAt < 0 {
		t.Fatal("the fixture has no Nodes: section")
	}
	cut := nodesAt + len("Nodes:")
	if !strings.HasPrefix(content, string(orig)[:cut]) {
		t.Errorf("the top-level keys before Nodes: changed:\n%s", content[:min(len(content), cut)])
	}
	if !reflect.DeepEqual(before.LogConfig, after.LogConfig) {
		t.Errorf("Log changed: %+v -> %+v", before.LogConfig, after.LogConfig)
	}
	if !reflect.DeepEqual(before.ConnectionConfig, after.ConnectionConfig) {
		t.Errorf("ConnectionConfig changed: %+v -> %+v", before.ConnectionConfig, after.ConnectionConfig)
	}
	if before.DnsConfigPath != after.DnsConfigPath || before.RouteConfigPath != after.RouteConfigPath ||
		before.InboundConfigPath != after.InboundConfigPath || before.OutboundConfigPath != after.OutboundConfigPath {
		t.Error("a top-level path key changed")
	}
	// Every original comment survives; a comment inside a converted entry
	// gains the rollback '#' in front of it.
	for _, line := range strings.Split(string(orig), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if !strings.Contains(content, line) && !strings.Contains(content, "#"+line) {
			t.Errorf("comment %q disappeared", line)
		}
	}
}

// TestLinkRealV03ConfigWithoutCompanionFiles is the real-world case: the
// sanitized v0.3 config is copied into a directory that does not hold the JSON
// files its top-level path keys point at. Those missing files are a problem
// the config already had before the conversion, so link must not block on
// them: it converts, warns about the pre-existing failures and leaves a
// loadable config, a backup and a 0600 token file behind.
func TestLinkRealV03ConfigWithoutCompanionFiles(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("testdata", "link_v03_real.yml"))
	if err != nil {
		t.Fatalf("read the real fixture: %v", err)
	}
	dir := t.TempDir()
	// Point the three path keys at files that are not there. The fixture's
	// absolute /etc/W1nCray paths may exist on a machine that runs W1nCray,
	// which would hide the pre-existing problem this test relies on.
	text := string(src)
	for _, name := range []string{"route.json", "custom_inbound.json", "custom_outbound.json"} {
		old := "/etc/W1nCray/" + name
		if !strings.Contains(text, old) {
			t.Fatalf("the fixture no longer references %s", old)
		}
		text = strings.Replace(text, old, yamlDQ(filepath.ToSlash(filepath.Join(dir, "missing-"+name))), 1)
	}
	cfgPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(cfgPath, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	orig := []byte(text)

	tokenFile := filepath.Join(dir, "token-source")
	if err := os.WriteFile(tokenFile, []byte("  fixture-machine-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := linkOptions{
		Panel:     "https://panel.example.com",
		Machine:   3,
		TokenFile: tokenFile,
		PortRange: "20000-40000",
	}
	var out bytes.Buffer
	if err := runLink(cfgPath, opts, &out); err != nil {
		t.Fatalf("link blocked on a pre-existing problem: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "转换前就有以下问题") {
		t.Errorf("the report does not warn about the pre-existing problems:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "missing-route.json") {
		t.Errorf("the warning does not name the missing file:\n%s", out.String())
	}

	after, err := panel.LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("the converted config must load: %v\n%s", err, out.String())
	}
	pc := after.Agent.Panel
	if pc == nil || !pc.Enabled || !pc.MachineNodes || pc.MachineID != 3 {
		t.Fatalf("Panel = %+v, want enabled machine mode for machine 3", pc)
	}
	if len(pc.NodeControllers) != 3 {
		t.Fatalf("NodeControllers has %d entries, want 3", len(pc.NodeControllers))
	}
	if len(after.NodesConfig) != 0 {
		t.Errorf("%d static nodes remain, want none", len(after.NodesConfig))
	}

	backups, err := filepath.Glob(cfgPath + ".bak-link-*")
	if err != nil || len(backups) != 1 {
		t.Fatalf("backups = %v (%v), want exactly one", backups, err)
	}
	backup, err := os.ReadFile(backups[0])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(backup, orig) {
		t.Error("the backup does not equal the original config")
	}

	tokenPath := filepath.Join(dir, "agent.token")
	fi, err := os.Stat(tokenPath)
	if err != nil {
		t.Fatalf("token file: %v", err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("token file mode = %04o, want 0600", fi.Mode().Perm())
	}
	if b, err := os.ReadFile(tokenPath); err != nil || string(b) != "fixture-machine-token" {
		t.Errorf("token file content is not the token (err %v, %d bytes)", err, len(b))
	}
}

// TestLinkSkipCheck: --skip-check writes the conversion even when the
// validation would report a problem the conversion introduces, and says so.
func TestLinkSkipCheck(t *testing.T) {
	dir, cfgPath := writeLinkFixture(t, linkFixture)
	// A certificate mode machine mode cannot use: without --skip-check this
	// conversion is refused (see TestLinkKeepsEveryFileOnValidationFailure).
	if err := os.WriteFile(cfgPath, []byte(strings.Replace(linkFixture, "CertMode: dns", "CertMode: bogus-mode", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := linkTestOpts()
	opts.SkipCheck = true
	var out bytes.Buffer
	if err := runLink(cfgPath, opts, &out); err != nil {
		t.Fatalf("link --skip-check failed: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "--skip-check") {
		t.Errorf("the report does not mention --skip-check:\n%s", out.String())
	}
	after, err := panel.LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("the converted config must load: %v", err)
	}
	if after.Agent == nil || after.Agent.Panel == nil || !after.Agent.Panel.Enabled {
		t.Fatal("the config was not converted")
	}
	if b, _ := filepath.Glob(cfgPath + ".bak-link-*"); len(b) != 1 {
		t.Errorf("backups = %v, want exactly one", b)
	}
	if fi, err := os.Stat(filepath.Join(dir, "agent.token")); err != nil {
		t.Fatalf("token file: %v", err)
	} else if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("token file mode = %04o, want 0600", fi.Mode().Perm())
	}
}

// TestLinkValidationLeavesNoBaselineFile: the temporary copy of the original
// config that the baseline comparison validates is removed again, also when
// the conversion is refused.
func TestLinkValidationLeavesNoBaselineFile(t *testing.T) {
	dir, cfgPath := writeLinkFixture(t, linkFixture)
	if err := os.WriteFile(cfgPath, []byte(strings.Replace(linkFixture, "CertMode: dns", "CertMode: bogus-mode", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runLink(cfgPath, linkTestOpts(), &bytes.Buffer{}); err == nil {
		t.Fatal("link accepted the invalid conversion")
	}
	left, err := filepath.Glob(filepath.Join(dir, ".link-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Errorf("temporary files left behind: %v", left)
	}
}

// TestLinkFailureKeyIgnoresVolatileParts pins the stable comparison key: the
// temporary file names of the run (and any backup timestamp) must not make the
// same pre-existing problem look new.
func TestLinkFailureKeyIgnoresVolatileParts(t *testing.T) {
	basePath := filepath.Join("tmp", ".link-baseline-123.yml")
	newPath := filepath.Join("tmp", ".link-987654.yml")
	base := "✗ read config " + basePath + ": While parsing config: boom"
	conv := "✗ read config " + newPath + ": While parsing config: boom"
	volatile := []string{basePath, newPath}
	if got, want := linkFailureKey(base, volatile...), linkFailureKey(conv, volatile...); got != want {
		t.Errorf("keys differ:\n  %q\n  %q", got, want)
	}
	if got := linkFailureKey("✗ backup config.yml.bak-link-20260101-000000 is bad"); strings.Contains(got, "20260101") {
		t.Errorf("the backup timestamp is not normalised: %q", got)
	}
}
