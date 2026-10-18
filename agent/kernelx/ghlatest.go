package kernelx

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/kernel/install"
	"github.com/W1nCwC/W1nCray/kernel/manifest"
	"github.com/W1nCwC/W1nCray/kernel/netutil"
)

// This file is the default-version path of the Xray kernel: with no pinned
// version the agent resolves the newest release of our own GitHub repository
// itself (the releases/latest redirect gives the tag, the same release's
// SHA256SUMS gives the asset hash) and installs it through the manifest-free
// direct installer, exactly like the panel's kernel_install does. The signed
// manifest stays the fallback when GitHub cannot be reached or the release
// carries no usable Xray asset. The logic mirrors install.sh's latest_tag /
// fetch_xray_kernel / xray_asset_name / xray_flavor.

// ownReleaseBase is the repository the agent and its Xray kernel are released from.
const ownReleaseBase = "https://github.com/W1nCwC/W1nCray"

const (
	xrayKernelName = "xray"
	// ghMetaTimeout bounds each metadata request (redirect, SHA256SUMS).
	ghMetaTimeout = 30 * time.Second
	// ghMaxSums caps the SHA256SUMS body we are willing to read.
	ghMaxSums = 1 << 20
)

// xrayRun mirrors the manifest entry and xraysvc's run block:
//
//	W1nCray-xray v0.9.2 (Xray-core 26.x)  ->  0.9.2
var xrayRun = manifest.Run{
	Binary:       "W1nCray-xray",
	VersionCmd:   []string{"version"},
	VersionRegex: `W1nCray-xray v?([0-9][0-9.]*)`,
}

var (
	reTag    = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$`)
	reSHA256 = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
)

// xrayAssetName is the release asset of the Xray kernel for an architecture,
// like install.sh's xray_asset_name.
func xrayAssetName(arch string, lite bool) string {
	if lite {
		return "W1nCray-xray-linux-" + arch + "-lite.gz"
	}
	return "W1nCray-xray-linux-" + arch + ".gz"
}

// installXrayLatest installs the newest GitHub release's Xray kernel. Every
// failure is returned unchanged so the caller can fall back to the manifest.
func (e *Ensurer) installXrayLatest(ctx context.Context) (driver.Installed, error) {
	plat := e.in.Platform()
	if plat.GOOS != "linux" {
		return driver.Installed{}, fmt.Errorf("no GitHub Xray build for %s", plat.GOOS)
	}
	base := strings.TrimRight(e.ghBase, "/")
	if u, err := url.Parse(base); err != nil || (u.Scheme != "https" && !(u.Scheme == "http" && e.allowHTTP)) {
		return driver.Installed{}, errors.New("release source scheme not allowed")
	}
	tag, err := e.latestTag(ctx, base)
	if err != nil {
		return driver.Installed{}, err
	}
	sums, err := e.fetchSums(ctx, base, tag)
	if err != nil {
		return driver.Installed{}, err
	}
	var asset, sha string
pick:
	for _, key := range plat.Keys() { // best architecture first (armv7 -> armv6 -> armv5)
		arch := strings.TrimPrefix(key, "linux/")
		flavors := []bool{false}
		if plat.OpenWrt {
			flavors = []bool{true, false} // the lite build first, like xray_flavor
		}
		for _, lite := range flavors {
			name := xrayAssetName(arch, lite)
			if h, ok := sums[name]; ok {
				asset, sha = name, h
				break pick
			}
		}
	}
	if asset == "" {
		return driver.Installed{}, fmt.Errorf("release %s lists no Xray kernel for %s", tag, plat.Key())
	}
	return e.in.InstallDirect(ctx, install.DirectInstall{
		Name:    xrayKernelName,
		URL:     base + "/releases/download/" + tag + "/" + asset,
		SHA256:  sha,
		Archive: manifest.ArchiveGz,
		To:      xrayRun.Binary,
		Run:     xrayRun,
	})
}

// latestTag follows releases/latest one hop and reads the tag off the
// redirect target, without downloading anything.
func (e *Ensurer) latestTag(ctx context.Context, base string) (string, error) {
	c := *e.ghClient
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	rctx, cancel := context.WithTimeout(ctx, ghMetaTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, base+"/releases/latest", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "W1nCray-kernel/1")
	resp, err := c.Do(req)
	if err != nil {
		return "", fmt.Errorf("resolving the latest release: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode < 300 || resp.StatusCode > 399 {
		return "", fmt.Errorf("latest release: HTTP %d, expected a redirect", resp.StatusCode)
	}
	loc, err := resp.Location()
	if err != nil {
		return "", fmt.Errorf("latest release: %w", err)
	}
	i := strings.LastIndex(loc.Path, "/tag/")
	if i < 0 {
		return "", errors.New("latest release: redirect carries no tag")
	}
	tag := loc.Path[i+len("/tag/"):]
	if !reTag.MatchString(tag) {
		return "", fmt.Errorf("latest release: unusable tag %q", tag)
	}
	return tag, nil
}

// fetchSums downloads and parses the release's SHA256SUMS into name -> hex.
func (e *Ensurer) fetchSums(ctx context.Context, base, tag string) (map[string]string, error) {
	rctx, cancel := context.WithTimeout(ctx, ghMetaTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, base+"/releases/download/"+tag+"/SHA256SUMS", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "W1nCray-kernel/1")
	resp, err := e.ghClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching SHA256SUMS of %s: %w", tag, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("SHA256SUMS of %s: HTTP %d", tag, resp.StatusCode)
	}
	out := map[string]string{}
	sc := bufio.NewScanner(io.LimitReader(resp.Body, ghMaxSums))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 2 || !reSHA256.MatchString(f[0]) {
			continue
		}
		out[strings.TrimPrefix(f[1], "*")] = strings.ToLower(f[0])
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading SHA256SUMS of %s: %w", tag, err)
	}
	return out, nil
}

// defaultClient is the HTTP client of the release lookups (proxy env incl. socks5).
func defaultClient() *http.Client { return netutil.NewClient() }
