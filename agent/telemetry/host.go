package telemetry

import (
	"context"
	"net"
	"os"
	"runtime"
	"sort"
	"strings"

	"github.com/W1nCwC/W1nCray/agent/wsproto"
)

// sampleHostInfo fills every field independently. A field that cannot be read
// stays at its zero value: the contract says "never invent a value"
// (agent/wsproto/wsproto.go) and the panel reads a zero as unknown.
//
// os and arch come from the Go runtime instead of kernel/platform.Detect():
// Detect runs `ldd --version` to learn the libc flavour, and a sampler that the
// agent calls every few minutes must not start an external process. libc has no
// field in HostInfo anyway — it belongs to hello.platform, which the wiring
// fills from platform.Detect() (design §2.4 R14).
func (c *Collector) sampleHostInfo(ctx context.Context) wsproto.HostInfo {
	var hi wsproto.HostInfo
	hi.OS = runtime.GOOS
	hi.Arch = runtime.GOARCH

	c.field("hostname", func() { hi.Hostname = hostname() })

	c.field("os info", func() {
		st, err := hostInfo(ctx)
		if err != nil || st == nil {
			return
		}
		hi.OSVersion = st.PlatformVersion
		hi.KernelVersion = st.KernelVersion
		hi.Virtualization = st.VirtualizationSystem
		if st.BootTime > 0 {
			hi.BootTime = int64(st.BootTime)
		}
	})

	c.field("cpu", func() {
		model, cores, threads := cpuModelAndCounts(ctx)
		hi.CPUModel, hi.CPUCores, hi.CPUThreads = model, cores, threads
	})

	c.field("memory totals", func() {
		memUse, swapUse := memoryUsage(ctx)
		hi.MemTotal, hi.SwapTotal = memUse.Total, swapUse.Total
	})

	c.field("disks", func() { hi.Disks = diskInfos(ctx) })

	c.field("ips", func() { hi.IPs = interfaceIPs() })

	c.field("timezone", func() { hi.Timezone = timezoneName() })

	return hi
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	return h
}

// cpuModelAndCounts returns the CPU model and the core counts of design R13:
// cpu_cores is the number of physical cores, cpu_threads the number of logical
// CPUs. Both are left at zero when the platform cannot report them.
func cpuModelAndCounts(ctx context.Context) (model string, cores, threads int) {
	if infos, err := cpuInfo(ctx); err == nil && len(infos) > 0 {
		model = strings.TrimSpace(infos[0].ModelName)
		if model == "" {
			model = strings.TrimSpace(infos[0].Model)
		}
	}
	if n, err := cpuCounts(ctx, false); err == nil && n > 0 {
		cores = n
	}
	if n, err := cpuCounts(ctx, true); err == nil && n > 0 {
		threads = n
	}
	return model, cores, threads
}

// diskInfos lists the mount points the panel may show, with the capacity of
// each. The dynamic used bytes are in Telemetry.
func diskInfos(ctx context.Context) []wsproto.DiskInfo {
	parts, err := partitions(ctx, false)
	if err != nil {
		return nil
	}
	seen := make(map[string]bool, len(parts))
	var out []wsproto.DiskInfo
	for _, p := range parts {
		if p.Mountpoint == "" || seen[p.Mountpoint] || !realFS(p.Fstype) {
			continue
		}
		seen[p.Mountpoint] = true
		u, err := usageOf(ctx, p.Mountpoint)
		if err != nil || u == nil {
			continue
		}
		out = append(out, wsproto.DiskInfo{Mount: p.Mountpoint, FSType: p.Fstype, Total: u.Total})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Mount < out[j].Mount })
	return out
}

// realFS rejects the pseudo filesystems the design lists. They describe RAM or
// kernel objects rather than storage, and showing them would report the same
// capacity several times.
func realFS(fstype string) bool {
	f := strings.ToLower(fstype)
	switch f {
	case "tmpfs", "devtmpfs", "overlay", "proc", "sysfs", "devfs", "ramfs":
		return false
	}
	return !strings.HasPrefix(f, "cgroup")
}

// interfaceIPs lists this machine's own addresses, read from the local
// interfaces only (no external probe, design §6-R4). An address configured on
// an interface is private when it is RFC 1918/4193 or carrier-grade NAT, and
// public when it is any other global unicast address (a VPS usually has its
// public address right on eth0). Behind NAT the public list stays empty.
func interfaceIPs() wsproto.IPs {
	addrs, err := interfaceAddrs()
	if err != nil {
		return wsproto.IPs{}
	}
	return classifyIPs(addrs)
}

// cgnat is 100.64.0.0/10 (RFC 6598): shared address space, never public.
var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

func classifyIPs(addrs []net.Addr) wsproto.IPs {
	seen := make(map[string]bool, len(addrs))
	var private, public []string
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		// Loopback and link-local addresses are the same on every host and
		// mean nothing to the panel.
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || !ip.IsGlobalUnicast() {
			continue
		}
		s := ip.String()
		if seen[s] {
			continue
		}
		seen[s] = true
		if ip.IsPrivate() || cgnat.Contains(ip) {
			private = append(private, s)
		} else {
			public = append(public, s)
		}
	}
	sort.Strings(private)
	sort.Strings(public)
	return wsproto.IPs{Private: private, Public: public}
}

// timezoneName prefers the zone the process was started with (TZ). Without it
// Go reports "Local", whose real name only the /etc/localtime symlink knows.
func timezoneName() string {
	if name := localZoneName(); name != "" && name != "Local" {
		return name
	}
	target, err := readlink("/etc/localtime")
	if err != nil {
		return ""
	}
	if i := strings.LastIndex(target, "zoneinfo/"); i >= 0 {
		return target[i+len("zoneinfo/"):]
	}
	return ""
}
