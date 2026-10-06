package portledger

import (
	"context"
	"errors"
	"net"
	"strconv"
	"testing"

	"github.com/W1nCwC/W1nCray/agent/driver"
)

func claim(proto, addr string, port int, owner string) driver.PortClaim {
	return driver.PortClaim{Proto: proto, Addr: addr, Port: port, Owner: owner}
}

func TestParsePorts(t *testing.T) {
	good := map[string][2]int{"8443": {8443, 8443}, "1": {1, 1}, "65535": {65535, 65535}, "20000-20009": {20000, 20009}}
	for s, want := range good {
		lo, hi, err := ParsePorts(s)
		if err != nil || lo != want[0] || hi != want[1] {
			t.Errorf("ParsePorts(%q) = %d,%d,%v", s, lo, hi, err)
		}
	}
	for _, s := range []string{"", "0", "65536", "-1", "1-", "-5", "5-5", "9-8", "08443", "+80", " 80", "80 ", "0x50", "1e3", "80-90-100", "１２３", "99999", "100000"} {
		if _, _, err := ParsePorts(s); err == nil {
			t.Errorf("ParsePorts(%q) accepted", s)
		}
	}
}

func TestExpand(t *testing.T) {
	cs, err := Expand("tcp", "127.0.0.1", "100-102", "a")
	if err != nil || len(cs) != 3 || cs[2].Port != 102 || cs[0].Owner != "a" {
		t.Fatalf("%v %v", cs, err)
	}
	if _, err := Expand("tcp", "", "x", "a"); err == nil {
		t.Fatal("bad ports accepted")
	}
}

func TestAddrOverlap(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"127.0.0.1", "127.0.0.1", true},
		{"127.0.0.1", "127.0.0.2", false},
		{"0.0.0.0", "10.1.2.3", true},
		{"10.1.2.3", "0.0.0.0", true},
		{"0.0.0.0", "::1", false},
		{"0.0.0.0", "::", true}, // dual-stack wildcard owns the v4 space
		{"::", "127.0.0.1", true},
		{"::", "::1", true},
		{"::1", "::2", false},
		{"::1", "::1", true},
		{"", "192.168.1.1", true},
		{"*", "::1", true},
		{"::ffff:10.0.0.1", "10.0.0.1", true}, // v4-mapped equals v4
		{"fe80::1%eth0", "fe80::1", true},
		{"example.invalid", "example.invalid", true},
		{"example.invalid", "other.invalid", false},
	}
	for _, c := range cases {
		if got := AddrOverlap(c.a, c.b); got != c.want {
			t.Errorf("AddrOverlap(%q,%q)=%v want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestDetectRules(t *testing.T) {
	// tcp and udp of the same port do not collide
	if got := Detect([]driver.PortClaim{claim("tcp", "0.0.0.0", 80, "a"), claim("udp", "0.0.0.0", 80, "b")}); len(got) != 0 {
		t.Fatalf("tcp/udp must not conflict: %v", got)
	}
	// wildcard vs specific, different owners
	got := Detect([]driver.PortClaim{claim("tcp", "0.0.0.0", 80, "a"), claim("tcp", "10.0.0.1", 80, "b")})
	if len(got) != 1 || got[0].Reason != "port claimed by two instances" {
		t.Fatalf("got %v", got)
	}
	// same owner twice is flagged distinctly
	got = Detect([]driver.PortClaim{claim("tcp", "10.0.0.1", 80, "a"), claim("TCP", "10.0.0.1", 80, "a")})
	if len(got) != 1 || got[0].Reason != "port claimed twice by the same instance" {
		t.Fatalf("got %v", got)
	}
	// different specific addresses are fine
	if got := Detect([]driver.PortClaim{claim("tcp", "10.0.0.1", 80, "a"), claim("tcp", "10.0.0.2", 80, "b")}); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
	// invalid claims are reported, not panicking
	got = Detect([]driver.PortClaim{claim("sctp", "10.0.0.1", 80, "a"), claim("tcp", "10.0.0.1", 0, "a"), claim("tcp", "bad host", 1, "a")})
	if len(got) != 3 {
		t.Fatalf("got %v", got)
	}
	// three-way overlap reports every pair, deterministically
	three := []driver.PortClaim{claim("tcp", "::", 7, "c"), claim("tcp", "0.0.0.0", 7, "b"), claim("tcp", "1.1.1.1", 7, "a")}
	g1, g2 := Detect(three), Detect([]driver.PortClaim{three[2], three[0], three[1]})
	if len(g1) != 3 || len(g2) != 3 {
		t.Fatalf("%v %v", g1, g2)
	}
	for i := range g1 {
		if g1[i] != g2[i] {
			t.Fatalf("not deterministic: %v vs %v", g1, g2)
		}
	}
}

func TestLedgerReservedConflicts(t *testing.T) {
	l := New()
	l.Reserve("node:main", claim("tcp", "0.0.0.0", 443, ""), claim("udp", "0.0.0.0", 443, ""))
	l.Reserve("node:other", claim("tcp", "0.0.0.0", 443, "")) // two reservations may overlap
	got := l.Conflicts([]driver.PortClaim{claim("tcp", "10.0.0.1", 443, "inst1"), claim("tcp", "10.0.0.1", 8443, "inst1")})
	if len(got) != 2 { // against both reservations
		t.Fatalf("got %v", got)
	}
	for _, c := range got {
		if c.Reason != "port reserved for another component" {
			t.Fatalf("reason %q", c.Reason)
		}
	}
	l.Unreserve("node:main")
	l.Unreserve("node:other")
	if got := l.Conflicts([]driver.PortClaim{claim("tcp", "10.0.0.1", 443, "inst1")}); len(got) != 0 {
		t.Fatalf("after unreserve: %v", got)
	}
}

func TestPreflightSkipsHeldAndMapsProbeErrors(t *testing.T) {
	l := New()
	probed := map[string]bool{}
	l.Prober = func(proto, addr string, port int) error {
		probed[proto+":"+strconv.Itoa(port)] = true
		switch port {
		case 2:
			return ErrInUse
		case 3:
			return ErrPermission
		case 4:
			return errors.New("cannot assign requested address")
		}
		return nil
	}
	l.Commit([]driver.PortClaim{claim("tcp", "0.0.0.0", 1, "old")})
	new := []driver.PortClaim{
		claim("tcp", "10.0.0.1", 1, "n"), // overlaps what we hold: not probed
		claim("tcp", "10.0.0.1", 2, "n"),
		claim("tcp", "10.0.0.1", 3, "n"),
		claim("tcp", "10.0.0.1", 4, "n"),
		claim("tcp", "10.0.0.1", 5, "n"),
	}
	got := l.Preflight(context.Background(), new)
	if probed["tcp:1"] {
		t.Error("held port was probed")
	}
	if len(got) != 2 || got[0].A.Port != 2 || got[1].A.Port != 4 {
		t.Fatalf("got %v", got)
	}
	if got[0].Reason != "port already in use by another process" {
		t.Fatalf("reason %q", got[0].Reason)
	}
}

func TestPreflightCancelled(t *testing.T) {
	l := New()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got := l.Preflight(ctx, []driver.PortClaim{claim("tcp", "127.0.0.1", 9, "a")})
	if len(got) != 1 {
		t.Fatalf("got %v", got)
	}
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func TestProbeRealBindTCP(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	if err := Probe("tcp", "127.0.0.1", port); !errors.Is(err, ErrInUse) {
		t.Fatalf("occupied port: %v", err)
	}
	if err := Probe("TCP", "127.0.0.1", port); !errors.Is(err, ErrInUse) {
		t.Fatalf("proto case: %v", err)
	}
	l.Close()
	if err := Probe("tcp", "127.0.0.1", port); err != nil {
		t.Fatalf("released port: %v", err)
	}
	// the probe must not leave the port bound
	l2, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatalf("port still bound after probe: %v", err)
	}
	l2.Close()
}

func TestProbeRealBindUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	if err := Probe("udp", "127.0.0.1", port); !errors.Is(err, ErrInUse) {
		t.Fatalf("occupied udp: %v", err)
	}
	// the same port over tcp is a different socket space
	if err := Probe("tcp", "127.0.0.1", port); errors.Is(err, ErrInUse) {
		t.Logf("note: tcp %d busy by chance: %v", port, err)
	}
	pc.Close()
	if err := Probe("udp", "127.0.0.1", port); err != nil {
		t.Fatalf("released udp: %v", err)
	}
}

func TestProbeBadInput(t *testing.T) {
	if err := Probe("sctp", "127.0.0.1", 80); err == nil {
		t.Error("bad proto accepted")
	}
	if err := Probe("tcp", "127.0.0.1", 0); err == nil {
		t.Error("port 0 accepted")
	}
	if err := Probe("tcp", "192.0.2.77", 54321); err == nil || errors.Is(err, ErrInUse) {
		t.Errorf("unassigned address should be a plain error, got %v", err)
	}
}

func TestPreflightAndCheckWithRealSockets(t *testing.T) {
	l := New()
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	busyPort := busy.Addr().(*net.TCPAddr).Port
	free := freeTCPPort(t)

	got := l.Preflight(context.Background(), []driver.PortClaim{
		claim("tcp", "127.0.0.1", busyPort, "a"),
		claim("tcp", "127.0.0.1", free, "b"),
	})
	if len(got) != 1 || got[0].A.Port != busyPort {
		t.Fatalf("preflight: %v", got)
	}

	// Commit a claim that nobody listens on: Check reports it; the busy one is fine.
	l.Commit([]driver.PortClaim{claim("tcp", "127.0.0.1", busyPort, "a"), claim("tcp", "127.0.0.1", free, "b")})
	f := l.Check(context.Background())
	if len(f) != 1 || f[0].Kind != FindNotListening || f[0].Claim.Port != free {
		t.Fatalf("check: %v", f)
	}
	// Once something listens, the finding disappears.
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(free))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if f := l.Check(context.Background()); len(f) != 0 {
		t.Fatalf("check after listen: %v", f)
	}
}

func TestCommitIsolation(t *testing.T) {
	l := New()
	in := []driver.PortClaim{claim("tcp", "1.1.1.1", 2, "a")}
	l.Commit(in)
	in[0].Port = 99
	out := l.Claims()
	if out[0].Port != 2 {
		t.Fatal("ledger aliases caller slice")
	}
	out[0].Port = 77
	if l.Claims()[0].Port != 2 {
		t.Fatal("Claims aliases internal slice")
	}
}
