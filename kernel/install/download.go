package install

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/W1nCwC/W1nCray/kernel"
	"github.com/W1nCwC/W1nCray/kernel/manifest"
)

const userAgent = "W1nCray-kernel/1"

// errTransient marks failures worth retrying on the same URL (the partial
// file is kept and the next attempt resumes with a Range request).
type errTransient struct{ err error }

func (e errTransient) Error() string { return e.err.Error() }
func (e errTransient) Unwrap() error { return e.err }

// errHash marks content that arrived completely but has the wrong hash.
type errHash struct{ got, want, url string }

func (e errHash) Error() string {
	return fmt.Sprintf("sha256 mismatch from %s: got %s want %s", e.url, e.got, e.want)
}

// download fetches t into part (a file in the target directory's .partial,
// never /tmp: on OpenWrt /tmp is RAM). Sources are tried in manifest order.
// The sha256 is computed while streaming; on success part holds exactly the
// bytes whose SHA-256 is t.ArchiveSHA256. A hash mismatch discards the file
// and moves on to the next source; if no source yields matching bytes the
// result is kernel.ErrVerify when any source served wrong content, else
// kernel.ErrDownload.
func (in *Installer) download(ctx context.Context, name, version string, t *manifest.Target, part string) error {
	var (
		errs      []string
		sawVerify bool
	)
	for _, raw := range t.URLs {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "https" && !(u.Scheme == "http" && in.cfg.AllowHTTP)) {
			errs = append(errs, fmt.Sprintf("%s: scheme not allowed", redactURL(raw)))
			continue
		}
		var last error
		for attempt := 0; attempt < in.cfg.Retries; attempt++ {
			if err := ctx.Err(); err != nil {
				return kernel.Wrap(kernel.ErrDownload, name, version, err, "aborted")
			}
			last = in.fetch(ctx, raw, part, t)
			if last == nil {
				in.logf("kernel %s@%s: downloaded from %s", name, version, redactURL(raw))
				return nil
			}
			var tr errTransient
			if !errors.As(last, &tr) {
				break
			}
			in.sleep(ctx, time.Duration(attempt+1)*in.cfg.RetryDelay)
		}
		var eh errHash
		if errors.As(last, &eh) {
			sawVerify = true
			_ = os.Remove(part)
		}
		if ctx.Err() != nil {
			return kernel.Wrap(kernel.ErrDownload, name, version, ctx.Err(), "aborted")
		}
		errs = append(errs, fmt.Sprintf("%s: %v", redactURL(raw), last))
		in.logf("kernel %s@%s: source failed: %s", name, version, errs[len(errs)-1])
	}
	kind := kernel.ErrDownload
	if sawVerify {
		kind = kernel.ErrVerify
	}
	return kernel.Newf(kind, name, version, "all %d sources failed: %s", len(t.URLs), strings.Join(errs, "; "))
}

func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "<invalid url>"
	}
	u.User = nil
	u.RawQuery = ""
	return u.String()
}

// fetch performs one HTTP attempt, resuming from the existing partial file.
func (in *Installer) fetch(ctx context.Context, rawURL, part string, t *manifest.Target) error {
	f, err := os.OpenFile(part, os.O_RDWR|os.O_CREATE, stateMode)
	if err != nil {
		return err
	}
	defer f.Close()

	off, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	if off > t.ArchiveSize {
		if err := f.Truncate(0); err != nil {
			return err
		}
		off = 0
	}

	h := sha256.New()
	if off > 0 { // re-hash what we already have so the sum covers the whole file
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return err
		}
		if _, err := io.Copy(h, f); err != nil {
			return err
		}
	}
	if off < t.ArchiveSize {
		if err := in.transfer(ctx, rawURL, f, h, &off, t.ArchiveSize); err != nil {
			return err
		}
	}
	if off != t.ArchiveSize {
		return errTransient{fmt.Errorf("incomplete: have %d of %d bytes", off, t.ArchiveSize)}
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != t.ArchiveSHA256 {
		return errHash{got: got, want: t.ArchiveSHA256, url: redactURL(rawURL)}
	}
	return f.Sync()
}

// transfer streams the body (from offset *off) into f and h, advancing *off.
func (in *Installer) transfer(ctx context.Context, rawURL string, f *os.File, h hash.Hash, off *int64, size int64) error {
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	if *off > 0 {
		req.Header.Set("Range", "bytes="+strconv.FormatInt(*off, 10)+"-")
	}
	resp, err := in.cfg.HTTPClient.Do(req)
	if err != nil {
		return errTransient{err}
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		if *off > 0 { // server ignored Range: start over
			if err := f.Truncate(0); err != nil {
				return err
			}
			if _, err := f.Seek(0, io.SeekStart); err != nil {
				return err
			}
			h.Reset()
			*off = 0
		}
		if resp.ContentLength >= 0 && resp.ContentLength != size {
			return fmt.Errorf("server reports %d bytes, manifest says %d", resp.ContentLength, size)
		}
	case http.StatusPartialContent:
		start, ok := contentRangeStart(resp.Header.Get("Content-Range"))
		if !ok || start != *off {
			return errTransient{fmt.Errorf("unexpected Content-Range %q for offset %d", resp.Header.Get("Content-Range"), *off)}
		}
	case http.StatusRequestedRangeNotSatisfiable:
		_ = f.Truncate(0)
		h.Reset()
		*off = 0
		return errTransient{errors.New("range not satisfiable, restarting")}
	default:
		if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
			return errTransient{fmt.Errorf("HTTP %d", resp.StatusCode)}
		}
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	// Stall watchdog: abort the request if no byte arrives for StallTimeout.
	wd := newWatchdog(in.cfg.StallTimeout, cancel)
	defer wd.stop()
	body := &watchReader{r: resp.Body, wd: wd}

	remain := size - *off
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(body, remain+1))
	*off += n
	if err != nil {
		return errTransient{err}
	}
	if *off > size {
		_ = f.Truncate(size)
		return fmt.Errorf("server sent more than the %d bytes in the manifest", size)
	}
	return nil
}

func contentRangeStart(v string) (int64, bool) {
	// "bytes 1000-1999/2000"
	v = strings.TrimSpace(v)
	if !strings.HasPrefix(v, "bytes ") {
		return 0, false
	}
	rest := strings.TrimPrefix(v, "bytes ")
	dash := strings.IndexByte(rest, '-')
	if dash <= 0 {
		return 0, false
	}
	n, err := strconv.ParseInt(rest[:dash], 10, 64)
	return n, err == nil
}

// sleep waits d or until ctx is done.
func (in *Installer) sleep(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

type watchdog struct {
	mu sync.Mutex
	t  *time.Timer
	d  time.Duration
}

func newWatchdog(d time.Duration, onStall func()) *watchdog {
	w := &watchdog{d: d}
	if d > 0 {
		w.t = time.AfterFunc(d, onStall)
	}
	return w
}

func (w *watchdog) kick() {
	w.mu.Lock()
	if w.t != nil {
		w.t.Reset(w.d)
	}
	w.mu.Unlock()
}

func (w *watchdog) stop() {
	w.mu.Lock()
	if w.t != nil {
		w.t.Stop()
	}
	w.mu.Unlock()
}

type watchReader struct {
	r  io.Reader
	wd *watchdog
}

func (w *watchReader) Read(p []byte) (int, error) {
	n, err := w.r.Read(p)
	if n > 0 {
		w.wd.kick()
	}
	return n, err
}
