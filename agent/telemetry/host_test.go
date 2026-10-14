package telemetry

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/shirou/gopsutil/v4/cpu"
)

func TestRealFS(t *testing.T) {
	cases := map[string]bool{
		"ext4":     true,
		"xfs":      true,
		"ntfs":     true,
		"":         true,
		"tmpfs":    false,
		"devtmpfs": false,
		"overlay":  false,
		"proc":     false,
		"sysfs":    false,
		"cgroup":   false,
		"cgroup2":  false,
		"CGROUP2":  false,
		"TMPFS":    false,
	}
	for fstype, want := range cases {
		if got := realFS(fstype); got != want {
			t.Errorf("realFS(%q) = %v, want %v", fstype, got, want)
		}
	}
}

func TestInterfaceIPsSplitsInterfaceAddresses(t *testing.T) {
	swap(t, &interfaceAddrs, func() ([]net.Addr, error) {
		return []net.Addr{
			&net.IPNet{IP: net.ParseIP("192.168.1.5"), Mask: net.CIDRMask(24, 32)},
			&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
			&net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)},
			&net.IPNet{IP: net.ParseIP("8.8.8.8"), Mask: net.CIDRMask(32, 32)},
			&net.IPNet{IP: net.ParseIP("2001:db8::1"), Mask: net.CIDRMask(64, 128)},
			&net.IPAddr{IP: net.ParseIP("10.0.0.1")},
			&net.IPNet{IP: net.ParseIP("192.168.1.5"), Mask: net.CIDRMask(24, 32)}, // duplicate
		}, nil
	})

	got := interfaceIPs()
	// Loopback (127.0.0.1) and link-local (fe80::1) are excluded on purpose: they are
	// the same on every host. Global addresses configured on an interface (8.8.8.8,
	// 2001:db8::1) are public: reading them is not a network probe.
	want := []string{"10.0.0.1", "192.168.1.5"}
	if len(got.Private) != len(want) {
		t.Fatalf("private IPs = %v, want %v", got.Private, want)
	}
	for i := range want {
		if got.Private[i] != want[i] {
			t.Fatalf("private IPs = %v, want %v", got.Private, want)
		}
	}
	if strings.Join(got.Public, ",") != "2001:db8::1,8.8.8.8" {
		t.Fatalf("public IPs = %v, want the interface's global addresses", got.Public)
	}
}

func TestInterfaceIPsOnError(t *testing.T) {
	swap(t, &interfaceAddrs, func() ([]net.Addr, error) { return nil, errors.New("boom") })
	got := interfaceIPs()
	if len(got.Private) != 0 || len(got.Public) != 0 {
		t.Fatalf("IPs = %+v, want empty", got)
	}
}

func TestTimezoneName(t *testing.T) {
	t.Run("from TZ", func(t *testing.T) {
		swap(t, &localZoneName, func() string { return "Asia/Tokyo" })
		swap(t, &readlink, func(string) (string, error) {
			t.Fatal("readlink called although the zone name is known")
			return "", nil
		})
		if got := timezoneName(); got != "Asia/Tokyo" {
			t.Fatalf("timezone = %q, want Asia/Tokyo", got)
		}
	})
	t.Run("from /etc/localtime", func(t *testing.T) {
		swap(t, &localZoneName, func() string { return "Local" })
		swap(t, &readlink, func(path string) (string, error) {
			if path != "/etc/localtime" {
				t.Fatalf("readlink(%q), want /etc/localtime", path)
			}
			return "/usr/share/zoneinfo/Asia/Shanghai", nil
		})
		if got := timezoneName(); got != "Asia/Shanghai" {
			t.Fatalf("timezone = %q, want Asia/Shanghai", got)
		}
	})
	t.Run("unreadable", func(t *testing.T) {
		swap(t, &localZoneName, func() string { return "Local" })
		swap(t, &readlink, func(string) (string, error) { return "", errors.New("boom") })
		if got := timezoneName(); got != "" {
			t.Fatalf("timezone = %q, want empty", got)
		}
	})
	t.Run("unexpected symlink target", func(t *testing.T) {
		swap(t, &localZoneName, func() string { return "" })
		swap(t, &readlink, func(string) (string, error) { return "/etc/localtime", nil })
		if got := timezoneName(); got != "" {
			t.Fatalf("timezone = %q, want empty", got)
		}
	})
}

func TestCPUModelAndCounts(t *testing.T) {
	swap(t, &cpuInfo, func(context.Context) ([]cpu.InfoStat, error) {
		return []cpu.InfoStat{{ModelName: " Intel Xeon E5 "}}, nil
	})
	var logicalArgs []bool
	swap(t, &cpuCounts, func(_ context.Context, logical bool) (int, error) {
		logicalArgs = append(logicalArgs, logical)
		if logical {
			return 8, nil
		}
		return 4, nil
	})

	model, cores, threads := cpuModelAndCounts(context.Background())
	if model != "Intel Xeon E5" {
		t.Fatalf("model = %q", model)
	}
	// Design R13: cores are physical (Counts(false)), threads logical (Counts(true)).
	if cores != 4 || threads != 8 {
		t.Fatalf("cores/threads = %d/%d, want 4/8", cores, threads)
	}
	if len(logicalArgs) != 2 || logicalArgs[0] || !logicalArgs[1] {
		t.Fatalf("Counts called with %v, want [false true]", logicalArgs)
	}
}

func TestCPUModelFallbacks(t *testing.T) {
	swap(t, &cpuInfo, func(context.Context) ([]cpu.InfoStat, error) {
		return []cpu.InfoStat{{Model: "fallback-model"}}, nil
	})
	swap(t, &cpuCounts, func(context.Context, bool) (int, error) { return 0, errors.New("boom") })

	model, cores, threads := cpuModelAndCounts(context.Background())
	if model != "fallback-model" {
		t.Fatalf("model = %q, want the Model fallback", model)
	}
	if cores != 0 || threads != 0 {
		t.Fatalf("cores/threads = %d/%d, want 0/0 when the platform cannot report them", cores, threads)
	}
}
