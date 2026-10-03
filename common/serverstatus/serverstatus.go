// Package serverstatus samples machine load for the panel status report.
package serverstatus

import (
	"os"
	"path/filepath"
	"runtime"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/mem"
)

// Status is a load sample. Sizes are bytes.
type Status struct {
	CPU                 float64
	MemTotal, MemUsed   uint64
	SwapTotal, SwapUsed uint64
	DiskTotal, DiskUsed uint64
}

// Get samples the machine. CPU usage is measured since the previous call.
func Get() (*Status, error) {
	s := new(Status)
	if p, err := cpu.Percent(0, false); err == nil && len(p) > 0 {
		s.CPU = min(max(p[0], 0), 100)
	}
	vm, err := mem.VirtualMemory()
	if err != nil {
		return nil, err
	}
	s.MemTotal, s.MemUsed = vm.Total, vm.Used
	if sw, err := mem.SwapMemory(); err == nil {
		s.SwapTotal, s.SwapUsed = sw.Total, sw.Used
	}
	if du, err := disk.Usage(rootPath()); err == nil {
		s.DiskTotal, s.DiskUsed = du.Total, du.Used
	}
	return s, nil
}

func rootPath() string {
	if runtime.GOOS == "windows" {
		if exe, err := os.Executable(); err == nil {
			return filepath.VolumeName(exe) + `\`
		}
		return `C:\`
	}
	return "/"
}
