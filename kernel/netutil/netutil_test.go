package netutil

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func proxyFor(t *testing.T, target string) string {
	t.Helper()
	r, _ := http.NewRequest("GET", target, nil)
	u, err := ProxyFunc()(r)
	if err != nil {
		t.Fatal(err)
	}
	if u == nil {
		return ""
	}
	return u.String()
}

func clearProxyEnv(t *testing.T) {
	for _, k := range []string{"ALL_PROXY", "all_proxy", "HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy"} {
		t.Setenv(k, "")
	}
}

func TestProxyFromEnv(t *testing.T) {
	clearProxyEnv(t)
	if got := proxyFor(t, "https://example.com/x"); got != "" {
		t.Fatalf("no env: %q", got)
	}
	t.Setenv("ALL_PROXY", "socks5h://127.0.0.1:7890")
	if got := proxyFor(t, "https://example.com/x"); got != "socks5h://127.0.0.1:7890" {
		t.Fatalf("ALL_PROXY https: %q", got)
	}
	if got := proxyFor(t, "http://example.com/x"); got != "socks5h://127.0.0.1:7890" {
		t.Fatalf("ALL_PROXY http: %q", got)
	}
	t.Setenv("HTTPS_PROXY", "http://proxy.local:3128")
	if got := proxyFor(t, "https://example.com/x"); got != "http://proxy.local:3128" {
		t.Fatalf("HTTPS_PROXY must beat ALL_PROXY: %q", got)
	}
	t.Setenv("NO_PROXY", "example.com")
	if got := proxyFor(t, "https://example.com/x"); got != "" {
		t.Fatalf("NO_PROXY ignored: %q", got)
	}
	if got := proxyFor(t, "http://127.0.0.1:9/x"); got != "" {
		t.Fatalf("loopback must never be proxied: %q", got)
	}
}

// miniSocks5 is a no-auth SOCKS5 server that resolves nothing itself: it
// records the requested host name and connects to backend instead.
func miniSocks5(t *testing.T, backend string) (addr string, hosts chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hosts = make(chan string, 8)
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				hdr := make([]byte, 2)
				if _, err := io.ReadFull(br, hdr); err != nil || hdr[0] != 5 {
					return
				}
				io.CopyN(io.Discard, br, int64(hdr[1]))
				c.Write([]byte{5, 0})
				req := make([]byte, 4)
				if _, err := io.ReadFull(br, req); err != nil || req[1] != 1 {
					return
				}
				var host string
				switch req[3] {
				case 3: // domain name: what socks5h sends
					l, _ := br.ReadByte()
					b := make([]byte, int(l))
					io.ReadFull(br, b)
					host = string(b)
				case 1:
					b := make([]byte, 4)
					io.ReadFull(br, b)
					host = net.IP(b).String()
				default:
					return
				}
				io.CopyN(io.Discard, br, 2) // port
				hosts <- host
				up, err := net.Dial("tcp", backend)
				if err != nil {
					c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				defer up.Close()
				c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				go io.Copy(up, br)
				io.Copy(c, up)
			}(c)
		}
	}()
	return ln.Addr().String(), hosts
}

func TestDownloadThroughSocks5h(t *testing.T) {
	clearProxyEnv(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "via-proxy:"+r.Host)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	sock, hosts := miniSocks5(t, u.Host)
	t.Setenv("ALL_PROXY", "socks5h://"+sock)

	// a non-loopback name so the proxy is not bypassed; socks5h must pass it as a domain
	resp, err := NewClient().Get("http://kernels.mirror.test:8080/file")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "via-proxy:kernels.mirror.test:8080" {
		t.Fatalf("body %q", body)
	}
	if h := <-hosts; h != "kernels.mirror.test" {
		t.Fatalf("socks5h must send the domain name to the proxy, got %q", h)
	}
}

func TestRedirectDowngradeRefused(t *testing.T) {
	clearProxyEnv(t)
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "plain") }))
	defer plain.Close()
	tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL, http.StatusFound)
	}))
	defer tls.Close()
	c := tls.Client()
	c.CheckRedirect = NewClient().CheckRedirect
	if _, err := c.Get(tls.URL); err == nil {
		t.Fatal("https -> http redirect was followed")
	}
}
