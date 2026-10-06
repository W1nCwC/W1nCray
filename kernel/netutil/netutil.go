// Package netutil builds the HTTP client used to fetch manifests and kernel
// archives (and by tools/manifestgen). It honours the usual proxy
// environment variables including ALL_PROXY and socks5/socks5h proxies,
// which net/http's ProxyFromEnvironment does not read for ALL_PROXY.
package netutil

import (
	"errors"
	"net/http"
	"net/url"
	"os"
	"time"

	"golang.org/x/net/http/httpproxy"
)

func firstEnv(names ...string) string {
	for _, n := range names {
		if v := os.Getenv(n); v != "" {
			return v
		}
	}
	return ""
}

// ProxyFunc reads HTTP_PROXY / HTTPS_PROXY / ALL_PROXY / NO_PROXY (upper or
// lower case) at call time. ALL_PROXY is the fallback for both schemes.
// Requests to localhost/loopback are never proxied.
func ProxyFunc() func(*http.Request) (*url.URL, error) {
	all := firstEnv("ALL_PROXY", "all_proxy")
	cfg := &httpproxy.Config{
		HTTPProxy:  firstEnv("HTTP_PROXY", "http_proxy"),
		HTTPSProxy: firstEnv("HTTPS_PROXY", "https_proxy"),
		NoProxy:    firstEnv("NO_PROXY", "no_proxy"),
	}
	if cfg.HTTPProxy == "" {
		cfg.HTTPProxy = all
	}
	if cfg.HTTPSProxy == "" {
		cfg.HTTPSProxy = all
	}
	f := cfg.ProxyFunc()
	return func(r *http.Request) (*url.URL, error) { return f(r.URL) }
}

// NewTransport returns a Transport with sane timeouts for large downloads.
// Compression is disabled: sizes and hashes refer to the exact bytes served.
func NewTransport() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = ProxyFunc()
	t.TLSHandshakeTimeout = 20 * time.Second
	t.ResponseHeaderTimeout = 45 * time.Second
	t.DisableCompression = true
	t.MaxIdleConnsPerHost = 2
	return t
}

// NewClient returns a client over NewTransport that refuses https->http
// redirect downgrades and redirect chains longer than 8.
func NewClient() *http.Client {
	return &http.Client{
		Transport: NewTransport(),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 8 {
				return errors.New("too many redirects")
			}
			if len(via) > 0 && via[0].URL.Scheme == "https" && req.URL.Scheme != "https" {
				return errors.New("refusing https to http redirect")
			}
			return nil
		},
	}
}
