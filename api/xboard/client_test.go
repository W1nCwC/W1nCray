package xboard

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

type recorded struct {
	method, path string
	query        map[string]string
	body         []byte
	ifNoneMatch  string
}

func newServer(t *testing.T, handler func(r *recorded, w http.ResponseWriter)) (*Client, *[]recorded) {
	t.Helper()
	var reqs []recorded
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		rec := recorded{method: r.Method, path: r.URL.Path, body: b, ifNoneMatch: r.Header.Get("If-None-Match"), query: map[string]string{}}
		for k := range r.URL.Query() {
			rec.query[k] = r.URL.Query().Get(k)
		}
		reqs = append(reqs, rec)
		handler(&rec, w)
	}))
	t.Cleanup(srv.Close)
	return New(Config{APIHost: srv.URL + "/", Key: "tok", NodeID: 5, NodeType: "vless"}), &reqs
}

func TestAuthAndConfigETag(t *testing.T) {
	c, reqs := newServer(t, func(r *recorded, w http.ResponseWriter) {
		if r.ifNoneMatch == `"abc"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"abc"`)
		// Values typed the way PHP may emit them.
		io.WriteString(w, `{"protocol":"vless","listen_ip":"0.0.0.0","server_port":"443","network":"tcp","networkSettings":[],"tls":"2","flow":"xtls-rprx-vision","decryption":null,"tls_settings":{"server_name":"a.com","server_port":"443","private_key":"k","short_id":"ab"},"base_config":{"push_interval":"30","pull_interval":45},"routes":[{"id":1,"match":["a.com","*.b.com"],"action":"block","action_value":null}],"cert_config":{"mode":"dns","domain":"n.com","dns_provider":"cloudflare","dns_env":{"CF_DNS_API_TOKEN":"x"}}}`)
	})
	nc, err := c.GetNodeConfig(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	r := (*reqs)[0]
	if r.method != http.MethodGet || r.path != "/api/v1/server/UniProxy/config" {
		t.Fatalf("request %s %s", r.method, r.path)
	}
	if r.query["token"] != "tok" || r.query["node_id"] != "5" || r.query["node_type"] != "vless" {
		t.Fatalf("auth query %v", r.query)
	}
	if nc.ServerPort != 443 || nc.TLS != 2 || nc.BaseConfig.PushInterval != 30 || nc.BaseConfig.PullInterval != 45 {
		t.Fatalf("weak typing failed: %+v", nc)
	}
	if !nc.NetworkSettingsObject().Empty() {
		t.Fatal("[] must decode as empty object")
	}
	if ts := nc.TLSConfig(); ts.PrivateKey != "k" || ts.ServerPort != "443" || ts.ShortID != "ab" {
		t.Fatalf("tls settings %+v", ts)
	}
	if len(nc.Routes) != 1 || nc.Routes[0].Action != "block" || len(nc.Routes[0].Match) != 2 {
		t.Fatalf("routes %+v", nc.Routes)
	}
	if cc := nc.CertConfig; cc.CertMode != "dns" || cc.DNSEnv["CF_DNS_API_TOKEN"] != "x" {
		t.Fatalf("cert config %+v", cc)
	}

	if _, err := c.GetNodeConfig(context.Background()); !errors.Is(err, ErrNotModified) {
		t.Fatalf("second request: %v, want ErrNotModified", err)
	}
	if (*reqs)[1].ifNoneMatch != `"abc"` {
		t.Fatal("ETag not sent")
	}
	c.ResetETags()
	if _, err := c.GetNodeConfig(context.Background()); err != nil {
		t.Fatalf("after reset: %v", err)
	}
}

func TestUsers(t *testing.T) {
	c, _ := newServer(t, func(r *recorded, w http.ResponseWriter) {
		w.Header().Set("ETag", `"u1"`)
		io.WriteString(w, `{"users":[{"id":1,"uuid":"a","speed_limit":null,"device_limit":null},{"id":"2","uuid":"b","speed_limit":"100","device_limit":3}]}`)
	})
	users, err := c.GetUsers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 || users[0].SpeedLimit != 0 || users[1].ID != 2 || users[1].SpeedLimit != 100 || users[1].DeviceLimit != 3 {
		t.Fatalf("users %+v", users)
	}
}

func TestReports(t *testing.T) {
	c, reqs := newServer(t, func(r *recorded, w http.ResponseWriter) {
		switch r.path {
		case "/api/v1/server/UniProxy/alivelist":
			io.WriteString(w, `{"alive":{"3":2,"9":"1"}}`)
		default:
			io.WriteString(w, `{"data":true}`)
		}
	})
	ctx := context.Background()
	if err := c.PushTraffic(ctx, map[int][2]int64{3: {10, 20}}); err != nil {
		t.Fatal(err)
	}
	if err := c.PushAlive(ctx, map[int][]string{3: {"1.2.3.4"}}); err != nil {
		t.Fatal(err)
	}
	if err := c.PushStatus(ctx, &Status{CPU: 12.5, Mem: Resource{Total: 100, Used: 50}}); err != nil {
		t.Fatal(err)
	}
	alive, err := c.GetAliveList(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if alive[3] != 2 || alive[9] != 1 {
		t.Fatalf("alive %v", alive)
	}

	var traffic map[string][]int64
	json.Unmarshal((*reqs)[0].body, &traffic)
	if (*reqs)[0].path != "/api/v1/server/UniProxy/push" || traffic["3"][0] != 10 || traffic["3"][1] != 20 {
		t.Fatalf("push %s %s", (*reqs)[0].path, (*reqs)[0].body)
	}
	var al map[string][]string
	json.Unmarshal((*reqs)[1].body, &al)
	if (*reqs)[1].path != "/api/v1/server/UniProxy/alive" || al["3"][0] != "1.2.3.4" {
		t.Fatalf("alive %s", (*reqs)[1].body)
	}
	var st map[string]any
	json.Unmarshal((*reqs)[2].body, &st)
	mem := st["mem"].(map[string]any)
	for _, k := range []string{"cpu", "mem", "swap", "disk"} {
		if _, ok := st[k]; !ok {
			t.Fatalf("status misses %s: %s", k, (*reqs)[2].body)
		}
	}
	if mem["total"].(float64) != 100 || mem["used"].(float64) != 50 {
		t.Fatalf("status %s", (*reqs)[2].body)
	}
	for _, r := range *reqs {
		if r.query["token"] != "tok" || r.query["node_id"] != "5" {
			t.Fatalf("%s missing auth: %v", r.path, r.query)
		}
	}
}

func TestStatusError(t *testing.T) {
	c, _ := newServer(t, func(r *recorded, w http.ResponseWriter) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		io.WriteString(w, `{"message":"Server does not exist"}`)
	})
	_, err := c.GetNodeConfig(context.Background())
	var se *StatusError
	if !errors.As(err, &se) || se.Code != 422 {
		t.Fatalf("err = %v", err)
	}
}
