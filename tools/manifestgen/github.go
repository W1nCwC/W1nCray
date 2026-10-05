package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// ghAsset is the subset of a GitHub release asset manifestgen uses.
type ghAsset struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	Digest string `json:"digest"` // "sha256:<hex>"; absent on old releases
	URL    string `json:"browser_download_url"`
}

type ghRelease struct {
	Tag        string    `json:"tag_name"`
	Prerelease bool      `json:"prerelease"`
	Draft      bool      `json:"draft"`
	Assets     []ghAsset `json:"assets"`
}

func (r *ghRelease) asset(name string) *ghAsset {
	for i := range r.Assets {
		if r.Assets[i].Name == name {
			return &r.Assets[i]
		}
	}
	return nil
}

// github talks to the GitHub REST API and to release download URLs.
type github struct {
	api    string // https://api.github.com
	token  string // optional, only sent to the API host
	client *http.Client
}

func (g *github) release(ctx context.Context, repo, tag string) (*ghRelease, error) {
	u := fmt.Sprintf("%s/repos/%s/releases/tags/%s", strings.TrimRight(g.api, "/"), repo, tag)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "w1ncray-manifestgen")
	if g.token != "" {
		req.Header.Set("Authorization", "Bearer "+g.token)
	}
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("GET %s: HTTP %d: %s", u, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var rel ghRelease
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&rel); err != nil {
		return nil, fmt.Errorf("decoding %s: %w", u, err)
	}
	if rel.Draft {
		return nil, fmt.Errorf("%s %s is a draft", repo, tag)
	}
	return &rel, nil
}

// fetch downloads a.URL into dst (via a temp file) and returns the sha256 and
// size of the bytes. An existing dst with the expected size is re-hashed
// instead of re-downloaded.
func (g *github) fetch(ctx context.Context, a *ghAsset, dst string) (string, int64, error) {
	if fi, err := os.Stat(dst); err == nil && fi.Size() == a.Size {
		if h, n, err := hashPath(dst); err == nil {
			return h, n, nil
		}
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return "", 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.URL, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("User-Agent", "w1ncray-manifestgen")
	resp, err := g.client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("GET %s: HTTP %d", a.URL, resp.StatusCode)
	}
	tmp := dst + ".part"
	f, err := os.Create(tmp)
	if err != nil {
		return "", 0, err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), resp.Body)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return "", 0, fmt.Errorf("downloading %s: %w", a.Name, err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// fetchSmall downloads a small text asset (checksum files).
func (g *github) fetchSmall(ctx context.Context, a *ghAsset) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "w1ncray-manifestgen")
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", a.URL, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 4<<20))
}

func hashPath(p string) (string, int64, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil)), n, err
}

// digestHex turns "sha256:<hex>" into "<hex>"; ok=false when absent/other.
func digestHex(d string) (string, bool) {
	h, found := strings.CutPrefix(d, "sha256:")
	if !found || len(h) != 64 {
		return "", false
	}
	return strings.ToLower(h), true
}

// parseSumFile parses sha256sum-style lines: "<hex>  <name>" or "<hex> *<name>".
func parseSumFile(b []byte) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 2 || len(f[0]) != 64 {
			continue
		}
		out[strings.TrimPrefix(f[1], "*")] = strings.ToLower(f[0])
	}
	return out
}

// parseDgst extracts the SHA2-256 value from an Xray ".dgst" file.
func parseDgst(b []byte) (string, bool) {
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok && strings.EqualFold(strings.TrimSpace(k), "SHA2-256") {
			v = strings.ToLower(strings.TrimSpace(v))
			if len(v) == 64 {
				return v, true
			}
		}
	}
	return "", false
}
