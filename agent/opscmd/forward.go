// This file registers the forward_probe command: the panel's reachability test
// for a user forward rule (W1NCRAY-FB-T5).
//
// The probe dials one TCP address from this machine and reports how long the
// connect took, or a stable error class. It carries a host, a port and a
// timeout and nothing else, so it can never read, write or name a local path.
// It answers immediately (a single dial bounded by timeout_ms), which keeps it
// a short command like audit_ctl.
//
// It is registered unconditionally: the command is part of this agent build.
// A panel must gate on the agent version (MIN_FORWARD_AGENT) before sending it,
// because an older agent answers unsupported instead of probing.

package opscmd

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/W1nCwC/W1nCray/agent/panelclient"
)

// Stable error codes of a forward_probe result (the panel branches on these).
const (
	ProbeErrInvalidArgs = "invalid_args"
	ProbeErrTimeout     = "timeout"
	ProbeErrRefused     = "refused"
	ProbeErrDNS         = "dns"
	ProbeErrUnreachable = "unreachable"
)

// Probe bounds from the frozen contract (docs/handoff/56 §6).
const (
	probeMinPort      = 1
	probeMaxPort      = 65535
	probeMinTimeoutMS = 500
	probeMaxTimeoutMS = 10000
	probeDefaultMS    = 3000
	probeMaxHostLen   = 253
)

// dialTimeout is net.DialTimeout behind a variable so tests can drive the
// timeout/unreachable classes deterministically. Production always uses
// net.DialTimeout.
var dialTimeout = net.DialTimeout

// forwardProbeArgs is the forward_probe payload:
// {"host":string,"port":int,"timeout_ms":int}. It is decoded strictly, so a
// panel that invents a field is refused instead of half-applied. TimeoutMS is
// a pointer so an omitted field takes the default while an explicit out-of-
// range value is rejected.
type forwardProbeArgs struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	TimeoutMS *int   `json:"timeout_ms,omitempty"`
}

// forwardProbeResult is the frozen result shape. RTTMS and ErrorCode are
// pointers so the failure form serialises both as JSON null.
type forwardProbeResult struct {
	OK        bool    `json:"ok"`
	RTTMS     *int64  `json:"rtt_ms"`
	ErrorCode *string `json:"error_code"`
}

// registerForward adds the forward_probe command. It needs no Deps: the probe
// is a plain TCP dial.
func registerForward(r *Registry, _ Deps) error {
	return r.Register(panelclient.CmdForwardProbe, forwardProbe)
}

// forwardProbe dials the target and classifies the outcome. Every answer is a
// done result with the frozen {ok,rtt_ms,error_code} body, so the panel reads
// one shape whether the probe connected or not; a failed status is reserved
// for a malformed request that never reached the dial.
func forwardProbe(_ context.Context, req Request, _ Completion) (Result, error) {
	var a forwardProbeArgs
	if err := decodeArgs(req.Args, &a); err != nil {
		return done(probeFailure(ProbeErrInvalidArgs)), nil
	}
	timeout, code := a.validate()
	if code != "" {
		return done(probeFailure(code)), nil
	}

	start := time.Now()
	conn, err := dialTimeout("tcp", net.JoinHostPort(a.Host, strconv.Itoa(a.Port)), timeout)
	if err != nil {
		return done(probeFailure(classifyProbeError(err))), nil
	}
	defer conn.Close() //nolint:errcheck // the connect is the measurement
	rtt := time.Since(start).Milliseconds()
	if rtt < 0 {
		rtt = 0
	}
	return done(forwardProbeResult{OK: true, RTTMS: &rtt}), nil
}

// validate checks the args against the contract and returns the dial timeout.
// An empty code means the args are usable.
func (a forwardProbeArgs) validate() (time.Duration, string) {
	if strings.TrimSpace(a.Host) == "" || len(a.Host) > probeMaxHostLen {
		return 0, ProbeErrInvalidArgs
	}
	if a.Port < probeMinPort || a.Port > probeMaxPort {
		return 0, ProbeErrInvalidArgs
	}
	ms := probeDefaultMS
	if a.TimeoutMS != nil {
		ms = *a.TimeoutMS
		if ms < probeMinTimeoutMS || ms > probeMaxTimeoutMS {
			return 0, ProbeErrInvalidArgs
		}
	}
	return time.Duration(ms) * time.Millisecond, ""
}

// probeFailure is the failure body: no RTT, one stable error class.
func probeFailure(code string) forwardProbeResult {
	return forwardProbeResult{OK: false, ErrorCode: &code}
}

// classifyProbeError maps a dial error to the contract's error classes, in the
// order the contract lists them: a timeout wins, then a refused connect, then
// a DNS failure (a *net.DNSError that is not a timeout), and everything else
// is unreachable.
func classifyProbeError(err error) string {
	var ne net.Error
	if (errors.As(err, &ne) && ne.Timeout()) || os.IsTimeout(err) {
		return ProbeErrTimeout
	}
	if errors.Is(err, syscall.ECONNREFUSED) || isRefusedErrno(err) {
		return ProbeErrRefused
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return ProbeErrDNS
	}
	return ProbeErrUnreachable
}

// wsaECONNREFUSED is WSAECONNREFUSED. On Windows the dialer reports the raw
// WinSock errno, which does not compare equal to syscall.ECONNREFUSED there, so
// a refused connect is recognised by both spellings. On Unix the extra check
// never matches (no errno has this value).
const wsaECONNREFUSED = syscall.Errno(10061)

// isRefusedErrno reports whether err carries the WinSock refused errno.
func isRefusedErrno(err error) bool {
	var errno syscall.Errno
	return errors.As(err, &errno) && errno == wsaECONNREFUSED
}
