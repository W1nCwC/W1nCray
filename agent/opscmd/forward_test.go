package opscmd

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/panelclient"
)

// decodeProbe reads the frozen {ok,rtt_ms,error_code} body of forward_probe.
func decodeProbe(t *testing.T, res json.RawMessage) forwardProbeResult {
	t.Helper()
	var out forwardProbeResult
	if err := json.Unmarshal(res, &out); err != nil {
		t.Fatalf("forward_probe result %s: %v", res, err)
	}
	return out
}

// runProbe executes forward_probe with raw args through the registry, so the
// registration and the strict decoding path are both exercised.
func runProbe(t *testing.T, args string) (string, forwardProbeResult) {
	t.Helper()
	reg := mustRegistry(t, Deps{})
	status, res := reg.Execute(context.Background(), panelclient.Command{
		ID:   "p1",
		Type: panelclient.CmdForwardProbe,
		Args: json.RawMessage(args),
	})
	return status, decodeProbe(t, res)
}

// stubDial replaces the dialer for one test and fails the test if the dial was
// reached when it should not have been. The returned counter is read by the
// caller.
func stubDial(t *testing.T, fn func(network, address string, timeout time.Duration) (net.Conn, error)) *int {
	t.Helper()
	orig := dialTimeout
	calls := 0
	dialTimeout = func(network, address string, timeout time.Duration) (net.Conn, error) {
		calls++
		return fn(network, address, timeout)
	}
	t.Cleanup(func() { dialTimeout = orig })
	return &calls
}

// timeoutError is a net.Error whose Timeout() is true, the shape a dial timeout
// has on the wire.
type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// TestForwardProbeDialSucceeds covers the ok path against a real local
// listener: done, ok, a non-negative RTT, no error class.
func TestForwardProbeDialSucceeds(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	status, res := runProbe(t, `{"host":"127.0.0.1","port":`+strconv.Itoa(port)+`}`)
	if status != panelclient.ResultDone {
		t.Fatalf("status = %q, want done", status)
	}
	if !res.OK {
		t.Fatalf("result = %+v, want ok", res)
	}
	if res.RTTMS == nil || *res.RTTMS < 0 {
		t.Errorf("rtt_ms = %v, want a non-negative integer", res.RTTMS)
	}
	if res.ErrorCode != nil {
		t.Errorf("error_code = %q, want null", *res.ErrorCode)
	}
}

// TestForwardProbeIPv6Address covers the address formatting: a bare IPv6
// literal must be joined into "[::1]:port", not "::1:port".
func TestForwardProbeIPv6Address(t *testing.T) {
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	status, res := runProbe(t, `{"host":"::1","port":`+strconv.Itoa(port)+`}`)
	if status != panelclient.ResultDone {
		t.Fatalf("status = %q, want done", status)
	}
	if !res.OK {
		t.Fatalf("result = %+v, want ok for [::1]:%d", res, port)
	}
	if res.RTTMS == nil || *res.RTTMS < 0 {
		t.Errorf("rtt_ms = %v, want a non-negative integer", res.RTTMS)
	}
}

// TestForwardProbeRefused covers the refused class: the port was listening and
// was closed, so the connect is actively refused.
func TestForwardProbeRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}

	_, res := runProbe(t, `{"host":"127.0.0.1","port":`+strconv.Itoa(port)+`}`)
	if res.OK {
		t.Fatalf("result = %+v, want a failure", res)
	}
	if res.RTTMS != nil {
		t.Errorf("rtt_ms = %v, want null on failure", *res.RTTMS)
	}
	if res.ErrorCode == nil || *res.ErrorCode != ProbeErrRefused {
		t.Fatalf("error_code = %v, want refused", res.ErrorCode)
	}
}

// TestForwardProbeTimeout covers the timeout class through the dialer seam.
func TestForwardProbeTimeout(t *testing.T) {
	stubDial(t, func(_, _ string, _ time.Duration) (net.Conn, error) {
		return nil, timeoutError{}
	})

	_, res := runProbe(t, `{"host":"192.0.2.1","port":80,"timeout_ms":500}`)
	if res.OK || res.ErrorCode == nil || *res.ErrorCode != ProbeErrTimeout {
		t.Fatalf("result = %+v, want timeout", res)
	}
}

// TestForwardProbeDNS covers the dns class: a reserved TLD never resolves and
// Go reports it as *net.DNSError (not a timeout). It uses the real resolver, so
// the classification is exercised end to end.
func TestForwardProbeDNS(t *testing.T) {
	_, res := runProbe(t, `{"host":"probe.invalid","port":80}`)
	if res.OK || res.ErrorCode == nil || *res.ErrorCode != ProbeErrDNS {
		t.Fatalf("result = %+v, want dns", res)
	}
	if res.RTTMS != nil {
		t.Errorf("rtt_ms = %v, want null on failure", *res.RTTMS)
	}
}

// TestForwardProbeUnreachable covers the catch-all class.
func TestForwardProbeUnreachable(t *testing.T) {
	stubDial(t, func(_, _ string, _ time.Duration) (net.Conn, error) {
		return nil, errors.New("no route to host")
	})

	_, res := runProbe(t, `{"host":"192.0.2.1","port":80}`)
	if res.OK || res.ErrorCode == nil || *res.ErrorCode != ProbeErrUnreachable {
		t.Fatalf("result = %+v, want unreachable", res)
	}
}

// TestForwardProbeDefaultTimeout covers the omitted timeout_ms default (3000ms)
// and an explicit in-range value.
func TestForwardProbeDefaultTimeout(t *testing.T) {
	cases := []struct {
		name string
		args string
		want time.Duration
	}{
		{"omitted", `{"host":"192.0.2.1","port":80}`, 3000 * time.Millisecond},
		{"explicit", `{"host":"192.0.2.1","port":80,"timeout_ms":500}`, 500 * time.Millisecond},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got time.Duration
			stubDial(t, func(_, _ string, timeout time.Duration) (net.Conn, error) {
				got = timeout
				return nil, errors.New("stopped")
			})
			runProbe(t, tc.args)
			if got != tc.want {
				t.Errorf("dial timeout = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestForwardProbeInvalidArgs covers the self-validation rules: every bad
// combination answers done with error_code invalid_args and never dials.
func TestForwardProbeInvalidArgs(t *testing.T) {
	cases := []struct{ name, args string }{
		{"empty body", ``},
		{"empty host", `{"host":"","port":80}`},
		{"blank host", `{"host":"   ","port":80}`},
		{"host too long", `{"host":"` + repeatByte('a', 254) + `","port":80}`},
		{"port zero", `{"host":"127.0.0.1","port":0}`},
		{"port too high", `{"host":"127.0.0.1","port":65536}`},
		{"negative port", `{"host":"127.0.0.1","port":-1}`},
		{"timeout too low", `{"host":"127.0.0.1","port":80,"timeout_ms":499}`},
		{"timeout too high", `{"host":"127.0.0.1","port":80,"timeout_ms":10001}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := stubDial(t, func(_, _ string, _ time.Duration) (net.Conn, error) {
				t.Error("the dial was reached with invalid args")
				return nil, errors.New("unexpected")
			})
			status, res := runProbe(t, tc.args)
			if status != panelclient.ResultDone {
				t.Fatalf("status = %q, want done (%+v)", status, res)
			}
			if res.OK || res.ErrorCode == nil || *res.ErrorCode != ProbeErrInvalidArgs {
				t.Fatalf("result = %+v, want invalid_args", res)
			}
			if *calls != 0 {
				t.Errorf("dial called %d times, want 0", *calls)
			}
		})
	}
}

// TestForwardProbeRejectsUnknownFields covers the strict decoding rule: a
// panel that invents a field is refused instead of half-applied.
func TestForwardProbeRejectsUnknownFields(t *testing.T) {
	calls := stubDial(t, func(_, _ string, _ time.Duration) (net.Conn, error) {
		t.Error("the dial was reached with an unknown field")
		return nil, errors.New("unexpected")
	})

	status, res := runProbe(t, `{"host":"127.0.0.1","port":80,"path":"/etc/shadow"}`)
	if status != panelclient.ResultDone {
		t.Fatalf("status = %q, want done", status)
	}
	if res.OK || res.ErrorCode == nil || *res.ErrorCode != ProbeErrInvalidArgs {
		t.Fatalf("result = %+v, want invalid_args", res)
	}
	if *calls != 0 {
		t.Errorf("dial called %d times, want 0", *calls)
	}
}

// repeatByte builds a host of exactly n bytes for the length boundary.
func repeatByte(b byte, n int) string {
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = b
	}
	return string(buf)
}
