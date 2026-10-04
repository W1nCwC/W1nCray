// Package limiter tracks per-user online IPs and enforces device limits and
// speed limits for connections entering the dispatcher.
package limiter

import (
	"errors"
	"sort"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// ErrDeviceLimit is returned when a new IP would exceed a user's device limit.
var ErrDeviceLimit = errors.New("device limit exceeded")

// minBurst keeps the token bucket large enough that a single buffer of a
// typical size can be admitted in one wait even for very low speed limits.
const minBurst = 64 * 1024

// User is the limiter view of a panel user.
type User struct {
	UID         int
	Email       string
	SpeedLimit  uint64 // bytes per second, 0 = unlimited
	DeviceLimit int    // 0 = unlimited
}

// Limiter holds the limiter state of every inbound, keyed by inbound tag.
type Limiter struct {
	inbounds sync.Map // tag -> *Inbound
}

// New creates an empty Limiter.
func New() *Limiter {
	return &Limiter{}
}

// AddInbound registers (or replaces) the state of an inbound. alwaysWrap makes
// every connection carry token buckets so that speed limits applied later
// (e.g. by auto speed limit) also throttle connections that are already open.
func (l *Limiter) AddInbound(tag string, alwaysWrap bool) *Inbound {
	in := &Inbound{tag: tag, alwaysWrap: alwaysWrap, users: make(map[string]*userState)}
	l.inbounds.Store(tag, in)
	return in
}

// RemoveInbound drops the state of an inbound.
func (l *Limiter) RemoveInbound(tag string) {
	l.inbounds.Delete(tag)
}

// Inbound returns the state of an inbound, or nil.
func (l *Limiter) Inbound(tag string) *Inbound {
	if v, ok := l.inbounds.Load(tag); ok {
		return v.(*Inbound)
	}
	return nil
}

// Acquire admits a connection of the user identified by email coming from ip
// on the inbound tag. A nil Session with a nil error means the connection is
// not managed by W1nCray (unknown inbound or user) and must pass untouched.
func (l *Limiter) Acquire(tag, email, ip string) (*Session, error) {
	in := l.Inbound(tag)
	if in == nil {
		return nil, nil
	}
	return in.Acquire(email, ip)
}

// Inbound is the limiter state of a single inbound (one panel node).
type Inbound struct {
	tag        string
	alwaysWrap bool

	mu    sync.RWMutex
	users map[string]*userState // email -> state
}

type ipState struct {
	refs     int
	lastSeen time.Time
}

type userState struct {
	uid int

	mu          sync.Mutex
	speed       uint64
	deviceLimit int
	up, down    *rate.Limiter
	ips         map[string]*ipState
	// globalAlive is the device count of this user across all nodes as
	// reported by the panel; lastReported is how many IPs this node
	// contributed to that count in its last report.
	globalAlive  int
	lastReported int
	// globalIPs are the user's IPs on all nodes from the panel's
	// sync.devices push (WebSocket); nil when not available.
	globalIPs map[string]struct{}
}

// SetUsers replaces the user table. State (online IPs, buckets) of users that
// stay in the table is kept, and their limits are updated in place so that
// open connections immediately follow the new speed limit.
func (in *Inbound) SetUsers(users []User) {
	next := make(map[string]*userState, len(users))
	in.mu.Lock()
	defer in.mu.Unlock()
	for _, u := range users {
		st, ok := in.users[u.Email]
		if !ok || st.uid != u.UID {
			st = &userState{uid: u.UID, ips: make(map[string]*ipState)}
		}
		st.setLimits(u.SpeedLimit, u.DeviceLimit)
		next[u.Email] = st
	}
	in.users = next
}

// UpdateUser changes the limits of a single user, if present.
func (in *Inbound) UpdateUser(email string, speed uint64, deviceLimit int) {
	in.mu.RLock()
	st := in.users[email]
	in.mu.RUnlock()
	if st != nil {
		st.setLimits(speed, deviceLimit)
	}
}

// SetGlobalAlive stores the panel-wide device counts (uid -> count).
func (in *Inbound) SetGlobalAlive(alive map[int]int) {
	in.mu.RLock()
	defer in.mu.RUnlock()
	for _, st := range in.users {
		st.mu.Lock()
		st.globalAlive = alive[st.uid]
		st.mu.Unlock()
	}
}

// SetGlobalDevices stores the panel-wide IPs of every user (uid -> IPs), as
// pushed by sync.devices. Users missing from the map have no devices.
func (in *Inbound) SetGlobalDevices(devices map[int][]string) {
	in.mu.RLock()
	defer in.mu.RUnlock()
	for _, st := range in.users {
		set := make(map[string]struct{}, len(devices[st.uid]))
		for _, ip := range devices[st.uid] {
			set[ip] = struct{}{}
		}
		st.mu.Lock()
		st.globalIPs = set
		st.mu.Unlock()
	}
}

// ClearGlobalDevices drops the panel-wide IPs (WebSocket disconnected), so
// device checks fall back to the alive list counts.
func (in *Inbound) ClearGlobalDevices() {
	in.mu.RLock()
	defer in.mu.RUnlock()
	for _, st := range in.users {
		st.mu.Lock()
		st.globalIPs = nil
		st.mu.Unlock()
	}
}

func (st *userState) setLimits(speed uint64, deviceLimit int) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.deviceLimit = deviceLimit
	st.speed = speed
	limit, burst := toRate(speed)
	for _, b := range []*rate.Limiter{st.up, st.down} {
		if b != nil {
			b.SetLimit(limit)
			b.SetBurst(burst)
		}
	}
}

func toRate(speed uint64) (rate.Limit, int) {
	if speed == 0 {
		return rate.Inf, minBurst
	}
	return rate.Limit(speed), int(max(speed, minBurst))
}

// Acquire implements the device limit check described in docs/PLAN.md §3.1.
func (in *Inbound) Acquire(email, ip string) (*Session, error) {
	in.mu.RLock()
	st := in.users[email]
	in.mu.RUnlock()
	if st == nil {
		return nil, nil
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	if s, ok := st.ips[ip]; ok {
		s.refs++
		s.lastSeen = time.Now()
	} else {
		if st.deviceLimit > 0 && st.devicesWith(ip) > st.deviceLimit {
			return nil, ErrDeviceLimit
		}
		st.ips[ip] = &ipState{refs: 1, lastSeen: time.Now()}
	}

	sess := &Session{st: st, ip: ip}
	if st.speed > 0 || in.alwaysWrap {
		if st.up == nil {
			limit, burst := toRate(st.speed)
			st.up = rate.NewLimiter(limit, burst)
			st.down = rate.NewLimiter(limit, burst)
		}
		sess.Up, sess.Down = st.up, st.down
	}
	return sess, nil
}

// devicesWith returns the panel-wide device count if ip (not yet connected
// here) is admitted. With sync.devices data it is the exact number of unique
// IPs across all nodes, as Xboard counts them; otherwise it estimates the
// other nodes' share from the alive list. Caller holds st.mu.
func (st *userState) devicesWith(ip string) int {
	if st.globalIPs != nil {
		n := len(st.ips) + 1
		for g := range st.globalIPs {
			if _, local := st.ips[g]; !local && g != ip {
				n++
			}
		}
		return n
	}
	return len(st.ips) + max(st.globalAlive-st.lastReported, 0) + 1
}

// AliveIPs returns, per uid, the IPs that are connected now or were seen
// within the window, and remembers how many IPs were reported per user so the
// next device check can tell this node's share of the panel-wide count.
// IPs without connections that fell out of the window are forgotten.
func (in *Inbound) AliveIPs(window time.Duration) map[int][]string {
	cutoff := time.Now().Add(-window)
	result := make(map[int][]string)
	in.mu.RLock()
	defer in.mu.RUnlock()
	for _, st := range in.users {
		st.mu.Lock()
		var ips []string
		for ip, s := range st.ips {
			if s.refs > 0 || s.lastSeen.After(cutoff) {
				ips = append(ips, ip)
			} else {
				delete(st.ips, ip)
			}
		}
		st.lastReported = len(ips)
		st.mu.Unlock()
		if len(ips) > 0 {
			sort.Strings(ips)
			result[st.uid] = ips
		}
	}
	return result
}

// Session is an admitted connection. Up/Down are nil when the connection does
// not need rate limiting.
type Session struct {
	st       *userState
	ip       string
	once     sync.Once
	Up, Down *rate.Limiter
}

// Limited reports whether the session carries token buckets.
func (s *Session) Limited() bool {
	return s != nil && s.Up != nil
}

// Release must be called once the connection ends.
func (s *Session) Release() {
	if s == nil {
		return
	}
	s.once.Do(func() {
		s.st.mu.Lock()
		defer s.st.mu.Unlock()
		if ip, ok := s.st.ips[s.ip]; ok {
			ip.refs--
			ip.lastSeen = time.Now()
		}
	})
}
