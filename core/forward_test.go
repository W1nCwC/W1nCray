package core

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/infra/conf"
)

// buildConfig output of the original code (before the Forward option
// existed) for these options. Forward off must reproduce it byte for byte.
const goldenNoForward = `{"dns":{"servers":[{"address":"1.1.1.1","domains":["domain:example.org"]},"localhost"]},"log":{"access":"none","error":"","loglevel":"warning"},"outbounds":[{"protocol":"freedom","tag":"direct"},{"protocol":"blackhole","tag":"w1ncray-block"}],"policy":{"levels":{"0":{"bufferSize":64,"connIdle":30,"downlinkOnly":4,"handshake":4,"statsUserDownlink":true,"statsUserUplink":true,"uplinkOnly":2}}},"routing":{"rules":null},"stats":{}}`

func goldenOptions() Options {
	return Options{
		LogLevel:    "warning",
		AccessPath:  "none",
		Connection:  ConnectionPolicy{Handshake: 4, ConnIdle: 30, UplinkOnly: 2, DownlinkOnly: 4, BufferSize: 64},
		NameServers: []NameServer{{Address: "1.1.1.1", Domains: []string{"domain:example.org"}}},
	}
}

func TestBuildConfigForwardOffIsUnchanged(t *testing.T) {
	b, _, err := buildConfig(goldenOptions())
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != goldenNoForward {
		t.Fatalf("config changed with Forward off:\n got  %s\n want %s", b, goldenNoForward)
	}
}

func TestBuildConfigForward(t *testing.T) {
	opts := goldenOptions()
	opts.Forward = &ForwardOptions{}
	b, _, err := buildConfig(opts)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Policy struct {
			Levels map[string]map[string]any `json:"levels"`
			System map[string]any            `json:"system"`
		} `json:"policy"`
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	// Level 0 (the nodes) is untouched.
	want0 := map[string]any{"bufferSize": 64., "connIdle": 30., "downlinkOnly": 4., "handshake": 4., "statsUserDownlink": true, "statsUserUplink": true, "uplinkOnly": 2.}
	if got := fmt.Sprint(cfg.Policy.Levels["0"]); got != fmt.Sprint(want0) {
		t.Fatalf("level 0 changed: %v", cfg.Policy.Levels["0"])
	}
	check := func(level uint32, want map[string]any) {
		t.Helper()
		got := cfg.Policy.Levels[fmt.Sprint(level)]
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("level %d = %v, want %v", level, got, want)
		}
	}
	check(LevelTCPLong, map[string]any{"bufferSize": 64., "connIdle": 3600., "downlinkOnly": 30., "handshake": 4., "uplinkOnly": 30.})
	check(LevelUDPShort, map[string]any{"bufferSize": 64., "connIdle": 60., "handshake": 4.})
	check(LevelUDPLong, map[string]any{"bufferSize": 64., "connIdle": 120., "handshake": 4.})
	check(LevelTCPDefault, map[string]any{"bufferSize": 64., "connIdle": 30., "downlinkOnly": 4., "handshake": 4., "uplinkOnly": 2.})
	for _, k := range []string{"statsInboundUplink", "statsInboundDownlink", "statsOutboundUplink", "statsOutboundDownlink"} {
		if cfg.Policy.System[k] != true {
			t.Fatalf("system.%s not enabled: %v", k, cfg.Policy.System)
		}
	}

	// The buffer size of the forward levels is configurable (kB).
	opts.Forward = &ForwardOptions{BufferKB: 16}
	b, _, err = buildConfig(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	for _, l := range []uint32{LevelTCPLong, LevelUDPShort, LevelUDPLong} {
		if got := cfg.Policy.Levels[fmt.Sprint(l)]["bufferSize"]; got != 16. {
			t.Fatalf("level %d bufferSize = %v, want 16", l, got)
		}
	}
	if got := cfg.Policy.Levels["103"]["bufferSize"]; got != 64. {
		t.Fatalf("tcp_default must keep the node bufferSize, got %v", got)
	}
}

func TestLevelForIdleProfile(t *testing.T) {
	for _, c := range []struct {
		profile string
		udp     bool
		want    uint32
	}{
		{"tcp_long", false, LevelTCPLong},
		{"tcp_default", false, LevelTCPDefault},
		{"udp_short", true, LevelUDPShort},
		{"udp_long", true, LevelUDPLong},
		{"", false, LevelTCPDefault},
		{"", true, LevelUDPShort},
	} {
		got, ok := LevelForIdleProfile(c.profile, c.udp)
		if !ok || got != c.want {
			t.Errorf("LevelForIdleProfile(%q, %v) = %d, %v; want %d", c.profile, c.udp, got, ok, c.want)
		}
	}
	if _, ok := LevelForIdleProfile("forever", false); ok {
		t.Error("unknown profile accepted")
	}
}

// The policy manager of a started instance carries the forward levels.
func TestForwardLevelsInInstance(t *testing.T) {
	opts := exampleOptions()
	opts.Forward = &ForwardOptions{}
	c, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	pm := c.Instance.GetFeature(policy.ManagerType()).(policy.Manager)
	for level, idle := range map[uint32]time.Duration{
		LevelTCPLong: 3600 * time.Second, LevelUDPShort: 60 * time.Second,
		LevelUDPLong: 120 * time.Second, LevelTCPDefault: 30 * time.Second, 0: 30 * time.Second,
	} {
		if got := pm.ForLevel(level).Timeouts.ConnectionIdle; got != idle {
			t.Errorf("level %d connIdle = %v, want %v", level, got, idle)
		}
	}
	if got := pm.ForLevel(LevelTCPLong).Buffer.PerConnection; got != 64*1024 {
		t.Errorf("tcp_long buffer = %d, want 65536", got)
	}
}

func addLevelForward(t *testing.T, c *Core, tag string, target int, level uint32) int {
	t.Helper()
	port := freePort(t)
	var oc conf.OutboundDetourConfig
	out := fmt.Sprintf(`{"protocol":"freedom","tag":%q,"settings":{"userLevel":%d}}`, tag+"-out", level)
	if err := json.Unmarshal([]byte(out), &oc); err != nil {
		t.Fatal(err)
	}
	ohc, err := oc.Build()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.AddOutbound(ohc); err != nil {
		t.Fatal(err)
	}
	raw := fmt.Sprintf(`{"tag":%q,"listen":"127.0.0.1","port":%d,"protocol":"dokodemo-door",
		"settings":{"address":"127.0.0.1","port":%d,"network":"tcp","userLevel":%d}}`, tag, port, target, level)
	var ic conf.InboundDetourConfig
	if err := json.Unmarshal([]byte(raw), &ic); err != nil {
		t.Fatal(err)
	}
	hc, err := ic.Build()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.AddInbound(hc); err != nil {
		t.Fatal(err)
	}
	rule := json.RawMessage(fmt.Sprintf(`{"inboundTag":[%q],"outboundTag":%q}`, tag, tag+"-out"))
	if err := c.Rules.SetNode(tag, &NodeRules{Head: []json.RawMessage{rule}}); err != nil {
		t.Fatal(err)
	}
	return port
}

// D-E: the node policy (level 0) cuts a connection that is idle for ConnIdle
// seconds, which is wrong for a forwarded SSH session. A forward level
// outlives it. Level 0 is given a 2 s idle timeout here to keep the test short.
func TestForwardLevelOutlivesNodeIdleTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("takes about 4 s")
	}
	if runtime.GOOS == "linux" {
		// On Linux the dokodemo→freedom pair qualifies for splice, and
		// upstream replaces the idle timer with 24 h on the splice path
		// (proxy.go:756), so the 2 s level-0 timeout never fires. The
		// semantics are covered on the other platforms.
		t.Skip("splice bypasses ConnIdle on linux")
	}
	opts := Options{
		LogLevel:   "none",
		Connection: ConnectionPolicy{Handshake: 4, ConnIdle: 2, UplinkOnly: 2, DownlinkOnly: 4, BufferSize: 64},
		Forward:    &ForwardOptions{},
	}
	c, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	echo := echoServer(t)
	node0 := addLevelForward(t, c, "plain", echo, 0)
	long := addLevelForward(t, c, "long", echo, LevelTCPLong)

	a := dialEcho(t, node0)
	b := dialEcho(t, long)
	// Poll for the level-0 idle timeout instead of a fixed sleep: teardown
	// lags under -race.
	deadline := time.Now().Add(20 * time.Second)
	for {
		a.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err := a.Read(make([]byte, 1))
		if err == nil {
			t.Fatal("unexpected data on an idle-timeout connection")
		}
		if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
			break // aborted: good
		}
		if time.Now().After(deadline) {
			t.Fatal("level-0 connection still open after its 2 s idle timeout")
		}
		time.Sleep(200 * time.Millisecond)
	}
	roundTrip(t, b) // still there
}

// D-E: with Forward on, per-inbound and per-outbound byte counters exist.
func TestForwardStats(t *testing.T) {
	for _, on := range []bool{false, true} {
		t.Run(fmt.Sprintf("forward=%v", on), func(t *testing.T) {
			opts := exampleOptions()
			if on {
				opts.Forward = &ForwardOptions{}
			}
			c, err := New(opts)
			if err != nil {
				t.Fatal(err)
			}
			if err := c.Start(); err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			echo := echoServer(t)
			port := addLevelForward(t, c, "fwd-1", echo, LevelTCPLong)

			conn := dialEcho(t, port)
			payload := make([]byte, 10000)
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err := conn.Write(payload); err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadFull(conn, payload); err != nil {
				t.Fatal(err)
			}
			conn.Close()

			inUp, inDown := c.InboundTraffic("fwd-1")
			outUp, outDown := c.OutboundTraffic("fwd-1-out")
			if !on {
				if inUp != nil || inDown != nil || outUp != nil || outDown != nil {
					t.Fatal("byte counters exist although Forward is off")
				}
				return
			}
			// 4 bytes of the ping + 10000 of the payload, each way. The
			// counters are updated as the connection tears down, which lags
			// under -race by a wide margin, so poll instead of reading once.
			// On linux the response direction is spliced and bypasses the
			// down counters entirely, so only the up direction is asserted
			// there (upstream behaviour, documented in the plan research).
			deadline := time.Now().Add(15 * time.Second)
			for {
				inUp, inDown := c.InboundTraffic("fwd-1")
				outUp, outDown := c.OutboundTraffic("fwd-1-out")
				want := map[string]stats.Counter{"in up": inUp, "out up": outUp}
				if runtime.GOOS != "linux" {
					want["in down"], want["out down"] = inDown, outDown
				}
				for name, ctr := range want {
					if ctr == nil {
						t.Errorf("%s counter missing", name)
					} else if ctr.Value() != 10004 {
						t.Errorf("%s counter = %d, want 10004", name, ctr.Value())
					}
				}
				if inUp != nil && inUp.Value() == 10004 || time.Now().After(deadline) {
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
		})
	}
}
