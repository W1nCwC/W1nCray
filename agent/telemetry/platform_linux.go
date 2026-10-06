//go:build linux

package telemetry

import (
	"os"
	"strconv"
	"strings"
)

// socketCounts counts sockets by reading /proc/net/* directly. The alternative,
// gopsutil's net.Connections("all"), allocates one struct per socket and is far
// too expensive for a five-second tick on a busy machine; only the row counts
// are needed. ok is false when no file could be read, so the caller reports
// null instead of a hard zero (design R8).
func socketCountsOS() (tcp, udp int, ok bool) {
	for _, f := range []struct {
		path string
		dst  *int
	}{
		{"/proc/net/tcp", &tcp},
		{"/proc/net/tcp6", &tcp},
		{"/proc/net/udp", &udp},
		{"/proc/net/udp6", &udp},
	} {
		n, err := countRows(f.path)
		if err != nil {
			continue
		}
		*f.dst += n
		ok = true
	}
	return tcp, udp, ok
}

// countRows counts data rows, skipping the header line of /proc/net files.
func countRows(path string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	rows := 0
	for _, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) != "" {
			rows++
		}
	}
	if rows > 0 {
		rows-- // header
	}
	return rows, nil
}

// selfRSSBytes reads the resident set size of this process from
// /proc/self/statm (field 2, in pages).
func selfRSSBytesOS() (uint64, bool) {
	b, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0, false
	}
	fields := strings.Fields(string(b))
	if len(fields) < 2 {
		return 0, false
	}
	pages, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0, false
	}
	return pages * uint64(os.Getpagesize()), true
}

// loadAverageOS reads the three load averages from /proc/loadavg. The gopsutil
// load package is not used: on several platforms it needs cgo or returns
// nothing, and this file is the only place that needs the values.
func loadAverageOS() (l1, l5, l15 float64, ok bool) {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, 0, 0, false
	}
	fields := strings.Fields(string(b))
	if len(fields) < 3 {
		return 0, 0, 0, false
	}
	vals := make([]float64, 3)
	for i := range vals {
		v, err := strconv.ParseFloat(fields[i], 64)
		if err != nil {
			return 0, 0, 0, false
		}
		vals[i] = v
	}
	return vals[0], vals[1], vals[2], true
}
