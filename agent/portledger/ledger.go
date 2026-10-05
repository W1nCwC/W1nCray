package portledger

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/W1nCwC/W1nCray/agent/driver"
)

// ReservedPrefix is prepended to the owner of externally reserved ports.
const ReservedPrefix = "reserved:"

// Ledger is the agent's registry of listeners it has committed to, plus ports
// reserved for things it does not manage (for example the node inbounds).
// It is safe for concurrent use.
type Ledger struct {
	// Prober binds an address to test it. Defaults to Probe; tests replace it.
	Prober func(proto, addr string, port int) error

	mu        sync.Mutex
	committed []driver.PortClaim
	reserved  map[string][]driver.PortClaim
}

// New returns an empty ledger.
func New() *Ledger {
	return &Ledger{reserved: map[string][]driver.PortClaim{}}
}

func (l *Ledger) probe(proto, addr string, port int) error {
	if l.Prober != nil {
		return l.Prober(proto, addr, port)
	}
	return Probe(proto, addr, port)
}

// Reserve registers listeners owned by something outside the reconciler
// (name identifies the owner, for example "node:main"). Reserved claims
// conflict with every instance claim. Calling Reserve again with the same name
// replaces the earlier reservation.
func (l *Ledger) Reserve(name string, claims ...driver.PortClaim) {
	cs := make([]driver.PortClaim, len(claims))
	for i, c := range claims {
		c.Owner = ReservedPrefix + name
		cs[i] = c
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.reserved == nil {
		l.reserved = map[string][]driver.PortClaim{}
	}
	if len(cs) == 0 {
		delete(l.reserved, name)
		return
	}
	l.reserved[name] = cs
}

// Unreserve drops a reservation.
func (l *Ledger) Unreserve(name string) { l.Reserve(name) }

// Commit replaces the registered instance claims with the given set. The
// caller is expected to have run Preflight on it first.
func (l *Ledger) Commit(claims []driver.PortClaim) {
	cs := append([]driver.PortClaim(nil), claims...)
	sortClaims(cs)
	l.mu.Lock()
	l.committed = cs
	l.mu.Unlock()
}

// Claims returns a sorted copy of the committed instance claims.
func (l *Ledger) Claims() []driver.PortClaim {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]driver.PortClaim(nil), l.committed...)
}

func (l *Ledger) reservedClaims() []driver.PortClaim {
	var out []driver.PortClaim
	names := make([]string, 0, len(l.reserved))
	for n := range l.reserved {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		out = append(out, l.reserved[n]...)
	}
	return out
}

// Conflicts is the static part of a preflight: overlaps inside claims and
// between claims and the reserved ports. It does not touch the system.
func (l *Ledger) Conflicts(claims []driver.PortClaim) []Conflict {
	l.mu.Lock()
	res := l.reservedClaims()
	l.mu.Unlock()

	all := make([]driver.PortClaim, 0, len(claims)+len(res))
	all = append(all, claims...)
	all = append(all, res...)
	var out []Conflict
	for _, c := range Detect(all) {
		// Two reservations overlapping each other is not the instance's fault;
		// at least one side must be an instance claim.
		if isReserved(c.A) && isReserved(c.B) {
			continue
		}
		if isReserved(c.A) || isReserved(c.B) {
			c.Reason = "port reserved for another component"
		}
		out = append(out, c)
	}
	return out
}

func isReserved(c driver.PortClaim) bool {
	return len(c.Owner) >= len(ReservedPrefix) && c.Owner[:len(ReservedPrefix)] == ReservedPrefix
}

// Preflight checks that a new set of claims can be bound: static conflicts
// first, then a real bind probe for every claim that does not overlap a
// listener the ledger already holds (those are ours and are expected to be
// bound until the driver replaces them). Probe results that cannot be
// interpreted (ErrPermission) are not reported as conflicts: the real bind
// will surface them.
func (l *Ledger) Preflight(ctx context.Context, claims []driver.PortClaim) []Conflict {
	out := l.Conflicts(claims)
	l.mu.Lock()
	held := append([]driver.PortClaim(nil), l.committed...)
	l.mu.Unlock()

	bad := map[driver.PortClaim]bool{}
	for _, c := range out {
		bad[c.A] = true
	}
	for _, c := range claims {
		if ctx.Err() != nil {
			out = append(out, Conflict{A: c, Reason: "preflight cancelled: " + ctx.Err().Error()})
			break
		}
		if ValidateClaim(c) != nil || bad[c] {
			continue
		}
		if overlapsAny(c, held) {
			continue
		}
		err := l.probe(c.Proto, c.Addr, c.Port)
		switch {
		case err == nil:
		case errors.Is(err, ErrInUse):
			out = append(out, Conflict{A: c, Reason: "port already in use by another process"})
		case errors.Is(err, ErrPermission):
		default:
			out = append(out, Conflict{A: c, Reason: "cannot bind: " + err.Error()})
		}
	}
	sortConflicts(out)
	return out
}

func overlapsAny(c driver.PortClaim, set []driver.PortClaim) bool {
	for _, h := range set {
		if ClaimsOverlap(c, h) {
			return true
		}
	}
	return false
}

// Finding kinds reported by Check.
const (
	// FindNotListening: a committed claim has no socket bound to it.
	FindNotListening = "not_listening"
	// FindProbeError: the probe could not decide (permission, bad address).
	FindProbeError = "probe_error"
)

// Finding is one discrepancy between the ledger and the real system.
type Finding struct {
	Claim  driver.PortClaim `json:"claim"`
	Kind   string           `json:"kind"`
	Detail string           `json:"detail,omitempty"`
}

func (f Finding) String() string {
	if f.Detail == "" {
		return fmt.Sprintf("%s: %s", claimString(f.Claim), f.Kind)
	}
	return fmt.Sprintf("%s: %s (%s)", claimString(f.Claim), f.Kind, f.Detail)
}

// Check reconciles the committed claims with reality. A claim is considered
// listening when a bind probe on it fails with "address in use"; a bind that
// succeeds means nobody holds the port, which is a finding. A listener that is
// held by some other process looks identical to ours: pure Go cannot attribute
// sockets without privileges, so use the driver's own Health for ownership.
func (l *Ledger) Check(ctx context.Context) []Finding {
	return l.CheckClaims(ctx, l.Claims())
}

// CheckClaims is Check for an explicit claim list.
func (l *Ledger) CheckClaims(ctx context.Context, claims []driver.PortClaim) []Finding {
	var out []Finding
	for _, c := range claims {
		if ctx.Err() != nil {
			out = append(out, Finding{Claim: c, Kind: FindProbeError, Detail: ctx.Err().Error()})
			break
		}
		err := l.probe(c.Proto, c.Addr, c.Port)
		switch {
		case err == nil:
			out = append(out, Finding{Claim: c, Kind: FindNotListening})
		case errors.Is(err, ErrInUse):
		default:
			out = append(out, Finding{Claim: c, Kind: FindProbeError, Detail: err.Error()})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return claimLess(out[i].Claim, out[j].Claim) })
	return out
}
