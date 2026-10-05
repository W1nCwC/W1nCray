package panelclient

import (
	"github.com/shirou/gopsutil/v4/host"

	"github.com/W1nCwC/W1nCray/common/serverstatus"
)

// defaultHost samples the machine for the report. Fields that cannot be read
// are left nil so the panel does not mistake them for zero.
func defaultHost() *HostStat {
	s, err := serverstatus.Get()
	if err != nil || s == nil {
		return nil
	}
	h := &HostStat{
		CPU:       &s.CPU,
		MemTotal:  &s.MemTotal,
		MemUsed:   &s.MemUsed,
		SwapTotal: &s.SwapTotal,
		SwapUsed:  &s.SwapUsed,
	}
	// serverstatus leaves the disk figures at zero when the root cannot be read.
	if s.DiskTotal > 0 {
		h.DiskTotal, h.DiskUsed = &s.DiskTotal, &s.DiskUsed
	}
	if up, err := host.Uptime(); err == nil {
		h.UptimeS = &up
	}
	return h
}
