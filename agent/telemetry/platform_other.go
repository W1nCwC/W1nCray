//go:build !linux

package telemetry

// The Linux-only probes report "unknown" rather than a fabricated zero, so the
// caller can leave the field out of the sample: telemetry.conns is null when
// the socket counts cannot be read (design R8), and the load average is simply
// absent on platforms that have no /proc/loadavg.

func socketCountsOS() (tcp, udp int, ok bool) { return 0, 0, false }

func selfRSSBytesOS() (uint64, bool) { return 0, false }

func loadAverageOS() (l1, l5, l15 float64, ok bool) { return 0, 0, 0, false }
