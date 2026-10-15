package xraynode

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	applog "github.com/xtls/xray-core/app/log"
	xlog "github.com/xtls/xray-core/common/log"

	"github.com/W1nCwC/W1nCray/agent/xrayapi"
)

// auditCapacity is the number of access-log entries the collector keeps. It is
// deliberately larger than the largest page (xrayapi.MaxAuditItems), so a
// caller that polls at the panel's cadence normally never sees dropped > 0.
const auditCapacity = 20000

// auditItem is one buffered access-log line: the kernel time (unix ms) and the
// line itself (already truncated to xrayapi.MaxAuditLine bytes).
type auditItem struct {
	t int64
	l string
}

// Collector is the kernel's bounded access-log ring buffer. It is created once
// per kernel process and survives every xray instance rebuild, so sequence
// numbers never restart inside one process.
//
// Disabled (the default) is the cheap path: append returns after one atomic
// load, without converting the message to a string.
type Collector struct {
	enabled atomic.Bool
	// epoch is the kernel process start (unix seconds). It is a process
	// constant: a caller that sees it change knows the kernel restarted and
	// its cursor belongs to a different process.
	epoch int64

	mu    sync.Mutex
	items []auditItem
	head  int
	n     int
	seq   uint64 // sequence number of the newest appended entry (0 = none)
	// floor is the highest sequence number that is no longer readable: the
	// ring buffer's overflow, or everything an off switch discarded. A cursor
	// at or below it is told how much it missed instead of being answered from
	// an entry that belongs to a different page.
	floor uint64
}

// NewCollector returns an empty, disabled collector for a kernel that started
// at epoch (unix seconds).
func NewCollector(epoch int64) *Collector {
	return &Collector{epoch: epoch, items: make([]auditItem, auditCapacity)}
}

// Epoch returns the kernel process start (unix seconds).
func (c *Collector) Epoch() int64 { return c.epoch }

// Enabled reports whether collection is on.
func (c *Collector) Enabled() bool { return c.enabled.Load() }

// SetEnabled turns collection on or off. Turning it off discards the buffer, so
// a later enable starts a fresh page; the sequence counter keeps increasing, so
// a caller holding an old cursor is told how much it missed instead of being
// served entries from before the switch.
func (c *Collector) SetEnabled(on bool) {
	c.enabled.Store(on)
	if !on {
		c.discard()
	}
}

// discard empties the ring buffer and records that everything up to the newest
// sequence number is no longer readable.
func (c *Collector) discard() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clearLocked()
	c.floor = c.seq
}

// clearLocked drops the buffered entries. The caller must hold c.mu.
func (c *Collector) clearLocked() {
	for i := 0; i < c.n; i++ {
		c.items[(c.head+i)%len(c.items)] = auditItem{}
	}
	c.head, c.n = 0, 0
}

// Append records one access-log line. It is a no-op when collection is off or
// line is empty, so the disabled path costs one atomic load.
func (c *Collector) Append(t int64, line string) {
	if !c.enabled.Load() || line == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.n == len(c.items) {
		// Full: drop the oldest entry and remember that it is gone.
		c.items[c.head] = auditItem{}
		c.head = (c.head + 1) % len(c.items)
		c.n--
		c.floor++
	}
	c.seq++
	c.items[(c.head+c.n)%len(c.items)] = auditItem{t: t, l: line}
	c.n++
}

// Batch returns up to max entries whose sequence number is greater than after,
// oldest first. max is clamped to xrayapi.MaxAuditItems (and defaults to it
// when it is not positive). More reports that entries beyond ToSeq are already
// buffered.
//
// Dropped is the number of entries the caller lost between after and FromSeq:
// the ring buffer's overflow, or entries an off switch discarded. A caller that
// keeps up with its ToSeq cursor never sees it non-zero, and the number never
// repeats on the next page.
func (c *Collector) Batch(after uint64, max int) xrayapi.AuditBatch {
	if max <= 0 || max > xrayapi.MaxAuditItems {
		max = xrayapi.MaxAuditItems
	}
	b := xrayapi.AuditBatch{Epoch: c.epoch, Items: []xrayapi.AuditItem{}}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seq <= c.floor {
		// Nothing was ever recorded, or everything was discarded.
		return b
	}
	oldest := c.seq - uint64(c.n) + 1
	if floor := c.floor + 1; floor > oldest {
		oldest = floor
	}
	from := oldest
	if after >= c.floor {
		from = after + 1
	} else {
		// The caller's cursor is below the floor: report the gap as dropped
		// instead of silently skipping it.
		b.Dropped = oldest - after - 1
	}
	if from > c.seq {
		// The caller is already up to date.
		return b
	}
	start := int(from - oldest)
	for i := start; i < c.n && len(b.Items) < max; i++ {
		it := c.items[(c.head+i)%len(c.items)]
		b.Items = append(b.Items, xrayapi.AuditItem{T: it.t, L: it.l})
	}
	if len(b.Items) == 0 {
		return b
	}
	b.FromSeq = from
	b.ToSeq = from + uint64(len(b.Items)) - 1
	b.More = b.ToSeq < c.seq
	return b
}

// auditHandler is the kernel's xray log handler. It is installed over the
// handler the xray instance registered (app/log) and does two things with
// every message: it offers accepted access messages to the collector, and it
// forwards everything to next, the replacement for the instance's own logger.
// Nothing about the existing output changes: next is built from the very same
// log configuration, so the console/file writers stay byte for byte the same.
type auditHandler struct {
	c    *Collector
	next xlog.Handler
	// closer releases the logger behind next (the app/log instance), whose
	// writers stay open for the lifetime of the xray instance otherwise.
	closer interface{ Close() error }
	// closeOnce guards closer.Close: the handler is replaced on every rebuild
	// and the instance that owns it is closed exactly once.
	closeOnce sync.Once
}

// Handle implements xlog.Handler.
func (h *auditHandler) Handle(msg xlog.Message) {
	// The disabled path must cost about one atomic read, so the type switch and
	// the (possibly expensive) String() happen only when collection is on and
	// the message is an accepted access message.
	if h.c.Enabled() {
		if am, ok := msg.(*xlog.AccessMessage); ok && am.Status == xlog.AccessAccepted {
			var sb strings.Builder
			h.c.Append(time.Now().UnixMilli(), truncateUTF8(am.String(), xrayapi.MaxAuditLine, &sb))
		}
	}
	if h.next != nil {
		h.next.Handle(msg)
	}
}

// Close releases the logger this handler replaced. It is idempotent.
func (h *auditHandler) Close() {
	if h.closer == nil {
		return
	}
	h.closeOnce.Do(func() { _ = h.closer.Close() })
}

// truncateUTF8 returns s shortened to at most n bytes without splitting a
// UTF-8 sequence. It uses buf (when it is non-nil) as its backing store, so
// recording a line allocates only the builder.
func truncateUTF8(s string, n int, buf *strings.Builder) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	if buf == nil {
		return s[:n]
	}
	buf.Reset()
	buf.Grow(n)
	buf.WriteString(s[:n])
	return buf.String()
}

// installAuditHandler replaces the global xray log handler with the audit
// handler. It must be called after the xray instance started, because
// app/log.New registers the instance's own handler while the instance is being
// created and would otherwise overwrite this one.
//
// The replacement logger is built from cfg — the same log configuration the
// instance was built from — so the access and error output keeps going to the
// same console or files with the same level filter and the same address
// masking.
func installAuditHandler(c *Collector, cfg *LogConfig) (*auditHandler, error) {
	inst, err := applog.New(context.Background(), auditLogConfig(cfg))
	if err != nil {
		return nil, err
	}
	h := &auditHandler{c: c, next: inst, closer: inst}
	xlog.RegisterHandler(h)
	return h, nil
}

// auditLogConfig maps the kernel's log configuration onto xray's log config
// exactly as infra/conf.LogConfig.Build does, so the replacement logger
// behaves like the instance's own one.
func auditLogConfig(cfg *LogConfig) *applog.Config {
	lc := &applog.Config{
		ErrorLogType:  applog.LogType_Console,
		AccessLogType: applog.LogType_Console,
	}
	level := ""
	if cfg != nil {
		level = strings.ToLower(cfg.Level)
		if cfg.AccessPath == "none" {
			lc.AccessLogType = applog.LogType_None
		} else if cfg.AccessPath != "" {
			lc.AccessLogPath = cfg.AccessPath
			lc.AccessLogType = applog.LogType_File
		}
		if cfg.ErrorPath == "none" {
			lc.ErrorLogType = applog.LogType_None
		} else if cfg.ErrorPath != "" {
			lc.ErrorLogPath = cfg.ErrorPath
			lc.ErrorLogType = applog.LogType_File
		}
	}
	switch level {
	case "debug":
		lc.ErrorLogLevel = xlog.Severity_Debug
	case "info":
		lc.ErrorLogLevel = xlog.Severity_Info
	case "error":
		lc.ErrorLogLevel = xlog.Severity_Error
	case "none":
		lc.ErrorLogType = applog.LogType_None
		lc.AccessLogType = applog.LogType_None
	default:
		lc.ErrorLogLevel = xlog.Severity_Warning
	}
	return lc
}
