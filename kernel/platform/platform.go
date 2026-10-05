// Package platform maps the machine the agent runs on to manifest target
// keys and decides whether a build variant can run on it.
//
// The facts come from the agent's own build settings (runtime/debug build
// info: GOARM, GOMIPS, GOMIPS64, GO386), which are a safe lower bound of the
// host's capabilities: an agent that runs there proves the host can run what
// the agent itself needs. The libc flavour is detected at run time. All inputs
// are injectable (Env) so tests can simulate any machine.
package platform

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
)

// Info describes a machine.
type Info struct {
	GOOS   string
	GOARCH string
	// ARM is the ARM architecture level (5, 6 or 7) when GOARCH is arm.
	ARM int
	// Float is "softfloat" or "hardfloat" for mips, mipsle (GOMIPS), mips64,
	// mips64le (GOMIPS64) and 386 (GO386=softfloat means "no SSE2"; otherwise
	// "hardfloat"). Empty for other architectures.
	Float string
	// Libc is "musl", "glibc" or "" (unknown or not Linux).
	Libc string
}

// Key is the primary manifest target key, e.g. "linux/amd64",
// "linux/armv7", "linux/mipsle".
func (i Info) Key() string { return i.Keys()[0] }

// Keys lists acceptable manifest target keys in order of preference. For ARM
// the lower levels follow: a GOARM=5 binary also runs on a v7 CPU, so a
// kernel without an armv7 build can fall back to armv6/armv5.
func (i Info) Keys() []string {
	if i.GOARCH == "arm" {
		lv := i.ARM
		if lv < 5 || lv > 7 {
			lv = 5
		}
		var out []string
		for v := lv; v >= 5; v-- {
			out = append(out, i.GOOS+"/armv"+strconv.Itoa(v))
		}
		return out
	}
	return []string{i.GOOS + "/" + i.GOARCH}
}

func (i Info) String() string {
	s := i.Key()
	if i.Float != "" {
		s += "/" + i.Float
	}
	if i.Libc != "" {
		s += "/" + i.Libc
	}
	return s
}

// Compatible reports why a build with the given variant string cannot run
// here ("" variant always passes). Variant is a free list of tokens
// ("hardfloat", "softfloat", "sse2", "musl-full", "glibc"...):
//
//   - hardfloat / sse2 need a machine with an FPU / SSE2, which an agent
//     built softfloat (GOMIPS=softfloat, GOMIPS64=softfloat, GO386=softfloat)
//     does not prove; softfloat builds run everywhere;
//   - glibc needs a glibc host (musl hosts cannot load it); an unknown libc
//     is let through, the post-install version self-check is the safety net;
//   - musl builds are assumed static and run on any libc.
func (i Info) Compatible(variant string) error {
	v := strings.ToLower(variant)
	if (strings.Contains(v, "hardfloat") || strings.Contains(v, "sse2")) && i.Float == "softfloat" {
		return &IncompatibleError{Variant: variant, Why: "needs an FPU/SSE2 but this agent is a softfloat build"}
	}
	if strings.Contains(v, "glibc") && i.Libc == "musl" {
		return &IncompatibleError{Variant: variant, Why: "needs glibc but this host uses musl"}
	}
	return nil
}

// IncompatibleError is returned by Compatible.
type IncompatibleError struct{ Variant, Why string }

func (e *IncompatibleError) Error() string {
	return "variant " + strconv.Quote(e.Variant) + " cannot run here: " + e.Why
}

// Env holds every input of Detect so tests can inject them.
type Env struct {
	GOOS, GOARCH string
	// Settings are the build settings (GOARM, GOMIPS, GOMIPS64, GO386).
	Settings map[string]string
	// Glob lists files matching a pattern (default filepath.Glob).
	Glob func(pattern string) ([]string, error)
	// Exists reports whether a path exists (default os.Stat).
	Exists func(path string) bool
	// ReadFile reads a file (default os.ReadFile).
	ReadFile func(path string) ([]byte, error)
	// Ldd returns the combined output of "ldd --version" (default: run it).
	Ldd func() (string, error)
}

// Detect inspects the running machine.
func Detect() Info {
	settings := map[string]string{}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			settings[s.Key] = s.Value
		}
	}
	return DetectEnv(Env{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Settings: settings})
}

// DetectEnv is Detect with injected inputs.
func DetectEnv(e Env) Info {
	if e.Glob == nil {
		e.Glob = filepath.Glob
	}
	if e.Exists == nil {
		e.Exists = func(p string) bool { _, err := os.Stat(p); return err == nil }
	}
	if e.ReadFile == nil {
		e.ReadFile = os.ReadFile
	}
	if e.Ldd == nil {
		e.Ldd = runLdd
	}
	info := Info{GOOS: e.GOOS, GOARCH: e.GOARCH}
	switch e.GOARCH {
	case "arm":
		info.ARM = parseARM(e.Settings["GOARM"])
		if info.ARM == 0 {
			info.ARM = cpuinfoARM(e.ReadFile)
		}
		if info.ARM == 0 {
			info.ARM = 5 // unknown: the most portable level
		}
	case "mips", "mipsle":
		info.Float = floatOr(e.Settings["GOMIPS"], "softfloat") // unknown: portable choice
	case "mips64", "mips64le":
		info.Float = floatOr(e.Settings["GOMIPS64"], "hardfloat") // Go's default
	case "386":
		if e.Settings["GO386"] == "softfloat" {
			info.Float = "softfloat"
		} else {
			info.Float = "hardfloat"
		}
	}
	if e.GOOS == "linux" {
		info.Libc = detectLibc(e)
	}
	return info
}

func floatOr(v, def string) string {
	switch v {
	case "softfloat", "hardfloat":
		return v
	}
	return def
}

// parseARM reads GOARM values such as "7", "6,softfloat", "5".
func parseARM(s string) int {
	if s == "" {
		return 0
	}
	if i := strings.IndexByte(s, ','); i >= 0 {
		s = s[:i]
	}
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 5 || n > 7 {
		return 0
	}
	return n
}

// cpuinfoARM reads "CPU architecture: 7" from /proc/cpuinfo.
func cpuinfoARM(read func(string) ([]byte, error)) int {
	b, err := read("/proc/cpuinfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if ok && strings.TrimSpace(k) == "CPU architecture" {
			v = strings.TrimSpace(v)
			if n, err := strconv.Atoi(strings.TrimRight(v, "TEJ")); err == nil && n >= 5 {
				if n > 7 {
					n = 7
				}
				return n
			}
		}
	}
	return 0
}

// detectLibc: "ldd --version" first (musl prints "musl libc" to stderr and
// exits 1; glibc prints "GNU libc"/"GLIBC"), then loader/distro files.
func detectLibc(e Env) string {
	if out, _ := e.Ldd(); out != "" {
		l := strings.ToLower(out)
		switch {
		case strings.Contains(l, "musl"):
			return "musl"
		case strings.Contains(l, "gnu libc"), strings.Contains(l, "glibc"), strings.Contains(l, "gnu c library"):
			return "glibc"
		}
	}
	if m, _ := e.Glob("/lib/ld-musl-*"); len(m) > 0 {
		return "musl"
	}
	if m, _ := e.Glob("/usr/lib/ld-musl-*"); len(m) > 0 {
		return "musl"
	}
	if e.Exists("/etc/alpine-release") || e.Exists("/etc/openwrt_release") {
		return "musl"
	}
	if e.Exists("/lib64/ld-linux-x86-64.so.2") || e.Exists("/lib/ld-linux.so.2") || e.Exists("/lib/ld-linux-aarch64.so.1") || e.Exists("/lib/ld-linux-armhf.so.3") {
		return "glibc"
	}
	if m, _ := e.Glob("/lib/*-linux-gnu/ld-linux-*"); len(m) > 0 {
		return "glibc"
	}
	return ""
}

func runLdd() (string, error) {
	path, err := exec.LookPath("ldd")
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "--version").CombinedOutput()
	if len(out) > 4096 {
		out = out[:4096]
	}
	return string(out), err
}
