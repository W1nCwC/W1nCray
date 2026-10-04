package node

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/shadowsocks_2022"

	_ "github.com/xtls/xray-core/main/distro/all"

	"github.com/W1nCwC/W1nCray/api/xboard"
	"github.com/W1nCwC/W1nCray/common/cert"
)

func testCert(t *testing.T) *certPaths {
	t.Helper()
	dir := t.TempDir()
	c, k, err := cert.SelfSigned("node.example.com", time.Hour*24)
	if err != nil {
		t.Fatal(err)
	}
	cf, kf := filepath.Join(dir, "c.crt"), filepath.Join(dir, "c.key")
	if err := os.WriteFile(cf, c, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kf, k, 0o600); err != nil {
		t.Fatal(err)
	}
	return &certPaths{CertFile: cf, KeyFile: kf}
}

func parseNode(t *testing.T, s string) *xboard.NodeConfig {
	t.Helper()
	nc := new(xboard.NodeConfig)
	if err := json.Unmarshal([]byte(s), nc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return nc
}

var testUsers = []nodeUser{
	{UID: 1, UUID: "7f6fd2d2-9a3d-4a8e-9f5b-1c2d3e4f5a6b"},
	{UID: 2, UUID: "0e1d2c3b-4a59-6877-8695-a4b3c2d1e0f9"},
}

func usersFor(p, tag string) []nodeUser {
	out := make([]nodeUser, len(testUsers))
	for i, u := range testUsers {
		u.Email = userEmail(p, tag, u.UID, u.UUID)
		out[i] = u
	}
	return out
}

// Node configs below follow Xboard ServerService::buildNodeConfig output.
func TestBuildInbounds(t *testing.T) {
	cases := []struct {
		name string
		json string
		tls  bool
	}{
		{"vmess-ws-tls", `{"protocol":"vmess","listen_ip":"0.0.0.0","server_port":10001,"network":"ws","networkSettings":{"path":"/ws","headers":{"Host":"cdn.example.com"}},"tls":1,"tls_settings":{"server_name":"node.example.com","allow_insecure":false},"multiplex":null,"base_config":{"push_interval":60,"pull_interval":60}}`, true},
		{"vmess-tcp-http-header", `{"protocol":"vmess","listen_ip":"0.0.0.0","server_port":10002,"network":"tcp","networkSettings":{"header":{"type":"http","request":{"path":["/"],"headers":{"Host":["a.com"]}}}},"tls":0,"tls_settings":[]}`, false},
		{"vmess-grpc-empty-settings", `{"protocol":"vmess","server_port":"10003","network":"grpc","networkSettings":[],"tls":0}`, false},
		{"vless-reality-vision", `{"protocol":"vless","listen_ip":"0.0.0.0","server_port":10004,"network":"tcp","networkSettings":null,"tls":2,"flow":"xtls-rprx-vision","decryption":null,"tls_settings":{"server_name":"www.microsoft.com","server_port":"443","public_key":"x","private_key":"uNNh2FBnbIe4CMT3VHGTe8wtJ7Tqc6tXeIpzQfXd0lQ","short_id":"0123abcd","allow_insecure":false}}`, false},
		{"vless-xhttp-tls", `{"protocol":"vless","server_port":10005,"network":"xhttp","networkSettings":{"path":"/x","host":"node.example.com","mode":"auto","extra":{"xPaddingBytes":"100-1000","sockopt":[]}},"tls":1,"flow":"","tls_settings":{"server_name":"node.example.com"}}`, true},
		{"vless-httpupgrade", `{"protocol":"vless","server_port":10006,"network":"httpupgrade","networkSettings":{"path":"/hu","host":"h.example.com"},"tls":0}`, false},
		{"trojan-grpc-tls", `{"protocol":"trojan","server_port":10007,"network":"grpc","networkSettings":{"serviceName":"svc"},"host":"node.example.com","server_name":"node.example.com","tls":1,"tls_settings":{"server_name":"node.example.com"}}`, true},
		{"trojan-tcp-reality", `{"protocol":"trojan","server_port":10008,"network":"tcp","tls":2,"tls_settings":{"server_name":"www.apple.com","server_port":"443","private_key":"uNNh2FBnbIe4CMT3VHGTe8wtJ7Tqc6tXeIpzQfXd0lQ","short_id":""}}`, false},
		{"ss-aes-gcm", `{"protocol":"shadowsocks","server_port":10009,"network":null,"networkSettings":null,"cipher":"aes-128-gcm","plugin":null,"plugin_opts":null,"server_key":null}`, false},
		{"ss-plugin-none", `{"protocol":"shadowsocks","server_port":10018,"cipher":"aes-256-gcm","plugin":"none","plugin_opts":null}`, false},
		{"ss-plugin-without-opts", `{"protocol":"shadowsocks","server_port":10019,"cipher":"aes-256-gcm","plugin":"obfs","plugin_opts":""}`, false},
		{"ss-chacha", `{"protocol":"shadowsocks","server_port":10010,"cipher":"chacha20-ietf-poly1305"}`, false},
		{"ss2022-aes128", `{"protocol":"shadowsocks","server_port":10011,"cipher":"2022-blake3-aes-128-gcm","server_key":"MTIzNDU2Nzg5MDEyMzQ1Ng=="}`, false},
		{"ss2022-aes256", `{"protocol":"shadowsocks","server_port":10012,"cipher":"2022-blake3-aes-256-gcm","server_key":"MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI="}`, false},
		{"hysteria2", `{"protocol":"hysteria","server_port":10013,"version":2,"host":"node.example.com","server_name":"node.example.com","tls_settings":{"server_name":"node.example.com","allow_insecure":false},"up_mbps":100,"down_mbps":500,"obfs":"salamander","obfs-password":"secret"}`, true},
		{"hysteria2-no-obfs", `{"protocol":"hysteria2","server_port":10014,"version":2,"up_mbps":0,"down_mbps":0,"obfs":null,"obfs-password":null}`, true},
		{"socks", `{"protocol":"socks","server_port":10015,"tls":0}`, false},
		{"http-tls", `{"protocol":"http","server_port":10016,"tls":1,"tls_settings":{"server_name":"node.example.com"}}`, true},
		{"vmess-kcp", `{"protocol":"vmess","server_port":10017,"network":"kcp","networkSettings":{"seed":"abc","header":{"type":"wechat-video"}},"tls":0}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nc := parseNode(t, tc.json)
			p, err := checkProtocol(nc)
			if err != nil {
				t.Fatal(err)
			}
			spec := &inboundSpec{tag: "node-1@test", protocol: p, node: nc, cfg: DefaultConfig()}
			if spec.needsTLS() != tc.tls {
				t.Fatalf("needsTLS = %v, want %v", spec.needsTLS(), tc.tls)
			}
			if tc.tls {
				spec.cert = testCert(t)
			}
			users := usersFor(p, spec.tag)
			ic, err := spec.build(users)
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			if ic.Tag != spec.tag {
				t.Fatalf("tag = %q", ic.Tag)
			}
			if hotUsers(p) {
				pu, err := spec.protocolUsers(users)
				if err != nil {
					t.Fatalf("protocolUsers: %v", err)
				}
				if len(pu) != len(users) {
					t.Fatalf("got %d users, want %d", len(pu), len(users))
				}
				for i, u := range pu {
					if u.Email != users[i].Email {
						t.Fatalf("email %q, want %q", u.Email, users[i].Email)
					}
					if _, err := u.ToMemoryUser(); err != nil {
						t.Fatalf("ToMemoryUser: %v", err)
					}
				}
			}
		})
	}
}

func TestBuildRejects(t *testing.T) {
	cases := map[string]string{
		"tuic":             `{"protocol":"tuic","server_port":1}`,
		"anytls":           `{"protocol":"anytls","server_port":1}`,
		"hysteria-v1":      `{"protocol":"hysteria","server_port":1,"version":1}`,
		"ss2022-chacha":    `{"protocol":"shadowsocks","server_port":1,"cipher":"2022-blake3-chacha20-poly1305"}`,
		"ss-real-plugin":   `{"protocol":"shadowsocks","server_port":1,"cipher":"aes-256-gcm","plugin":"obfs","plugin_opts":"obfs=http;obfs-host=www.bing.com"}`,
		"h2":               `{"protocol":"vmess","server_port":1,"network":"h2"}`,
		"tls-without-cert": `{"protocol":"vmess","server_port":1,"tls":1}`,
		"reality-no-key":   `{"protocol":"vless","server_port":1,"tls":2,"tls_settings":{"server_name":"a.com"}}`,
		"reality-ws":       `{"protocol":"vless","server_port":1,"network":"ws","tls":2,"tls_settings":{"server_name":"a.com","private_key":"uNNh2FBnbIe4CMT3VHGTe8wtJ7Tqc6tXeIpzQfXd0lQ"}}`,
		"bad-port":         `{"protocol":"vmess","server_port":0}`,
	}
	for name, js := range cases {
		t.Run(name, func(t *testing.T) {
			nc := parseNode(t, js)
			p, err := checkProtocol(nc)
			if err != nil {
				return
			}
			spec := &inboundSpec{tag: "t", protocol: p, node: nc, cfg: DefaultConfig()}
			if _, err := spec.build(usersFor(p, "t")); err == nil {
				t.Fatal("expected error")
			} else {
				t.Log(err)
			}
		})
	}
}

// Xboard: Helper::uuidToBase64($uuid, $len) = base64_encode(substr($uuid, 0, $len)).
func TestSS2022UserKey(t *testing.T) {
	uuid := "7f6fd2d2-9a3d-4a8e-9f5b-1c2d3e4f5a6b"
	if got, want := ss2022UserKey(uuid, 16), "N2Y2ZmQyZDItOWEzZC00YQ=="; got != want {
		t.Fatalf("16: got %s want %s", got, want)
	}
	if got, want := ss2022UserKey(uuid, 32), "N2Y2ZmQyZDItOWEzZC00YThlLTlmNWItMWMyZDNlNGY="; got != want {
		t.Fatalf("32: got %s want %s", got, want)
	}

	nc := parseNode(t, `{"protocol":"shadowsocks","server_port":1,"cipher":"2022-blake3-aes-128-gcm","server_key":"MTIzNDU2Nzg5MDEyMzQ1Ng=="}`)
	spec := &inboundSpec{tag: "t", protocol: protoShadowsocks, node: nc, cfg: DefaultConfig()}
	users, err := spec.protocolUsers(usersFor(protoShadowsocks, "t"))
	if err != nil {
		t.Fatal(err)
	}
	acc, err := users[0].Account.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	if k := acc.(*shadowsocks_2022.Account).Key; k != "N2Y2ZmQyZDItOWEzZC00YQ==" {
		t.Fatalf("account key %s", k)
	}
}

func TestEmails(t *testing.T) {
	if e := userEmail(protoVMess, "node-1@h", 9, "u"); e != "node-1@h|9" {
		t.Fatal(e)
	}
	if e := userEmail(protoSocks, "node-1@h", 9, "u"); e != "u" {
		t.Fatal(e)
	}
	var _ = protocol.User{}
	if !strings.Contains(userEmail(protoTrojan, "a", 1, "b"), "|") {
		t.Fatal("separator")
	}
}
