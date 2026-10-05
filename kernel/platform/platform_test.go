package platform

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func env(goos, goarch string, settings map[string]string, files ...string) Env {
	have := map[string]bool{}
	for _, f := range files {
		have[f] = true
	}
	return Env{
		GOOS: goos, GOARCH: goarch, Settings: settings,
		Glob: func(pat string) ([]string, error) {
			prefix := strings.TrimSuffix(pat, "*")
			var out []string
			for f := range have {
				if strings.HasPrefix(f, prefix) {
					out = append(out, f)
				}
			}
			return out, nil
		},
		Exists:   func(p string) bool { return have[p] },
		ReadFile: func(string) ([]byte, error) { return nil, os.ErrNotExist },
		Ldd:      func() (string, error) { return "", errors.New("no ldd") },
	}
}

func TestKeys(t *testing.T) {
	for _, c := range []struct {
		name string
		e    Env
		keys string
		any  string // Info.String()
	}{
		{"amd64", env("linux", "amd64", nil), "linux/amd64", ""},
		{"386 sse2", env("linux", "386", map[string]string{"GO386": "sse2"}), "linux/386", "hardfloat"},
		{"386 softfloat", env("linux", "386", map[string]string{"GO386": "softfloat"}), "linux/386", "softfloat"},
		{"arm64", env("linux", "arm64", nil), "linux/arm64", ""},
		{"arm v7", env("linux", "arm", map[string]string{"GOARM": "7"}), "linux/armv7,linux/armv6,linux/armv5", ""},
		{"arm v6", env("linux", "arm", map[string]string{"GOARM": "6"}), "linux/armv6,linux/armv5", ""},
		{"arm v5", env("linux", "arm", map[string]string{"GOARM": "5"}), "linux/armv5", ""},
		{"arm v7 with float suffix", env("linux", "arm", map[string]string{"GOARM": "7,hardfloat"}), "linux/armv7,linux/armv6,linux/armv5", ""},
		{"arm unknown -> safest", env("linux", "arm", nil), "linux/armv5", ""},
		{"loong64", env("linux", "loong64", nil), "linux/loong64", ""},
		{"riscv64", env("linux", "riscv64", nil), "linux/riscv64", ""},
		{"mips soft", env("linux", "mips", map[string]string{"GOMIPS": "softfloat"}), "linux/mips", "softfloat"},
		{"mipsle hard", env("linux", "mipsle", map[string]string{"GOMIPS": "hardfloat"}), "linux/mipsle", "hardfloat"},
		{"mipsle unknown -> soft", env("linux", "mipsle", nil), "linux/mipsle", "softfloat"},
		{"mips64", env("linux", "mips64", nil), "linux/mips64", "hardfloat"},
		{"mips64le soft", env("linux", "mips64le", map[string]string{"GOMIPS64": "softfloat"}), "linux/mips64le", "softfloat"},
		{"windows", env("windows", "amd64", nil), "windows/amd64", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			i := DetectEnv(c.e)
			if got := strings.Join(i.Keys(), ","); got != c.keys {
				t.Errorf("keys %s want %s", got, c.keys)
			}
			if i.Key() != strings.Split(c.keys, ",")[0] {
				t.Errorf("Key() = %s", i.Key())
			}
			if c.any != "" && !strings.Contains(i.String(), c.any) {
				t.Errorf("String() = %s lacks %s", i.String(), c.any)
			}
		})
	}
}

func TestARMFromCPUInfoWhenBuildInfoMissing(t *testing.T) {
	e := env("linux", "arm", nil)
	e.ReadFile = func(string) ([]byte, error) {
		return []byte("processor\t: 0\nCPU architecture: 7\nCPU variant\t: 0x3\n"), nil
	}
	if got := DetectEnv(e); got.ARM != 7 {
		t.Fatalf("ARM=%d", got.ARM)
	}
	e.ReadFile = func(string) ([]byte, error) { return []byte("CPU architecture: 5TEJ\n"), nil }
	if got := DetectEnv(e); got.ARM != 5 {
		t.Fatalf("ARM=%d", got.ARM)
	}
}

func TestLibc(t *testing.T) {
	ld := func(out string) func(*Env) {
		return func(e *Env) { e.Ldd = func() (string, error) { return out, errors.New("exit 1") } }
	}
	for _, c := range []struct {
		name  string
		files []string
		mod   func(*Env)
		want  string
	}{
		{"musl by ldd", nil, ld("musl libc (x86_64)\nVersion 1.2.4\nDynamic Program Loader\n"), "musl"},
		{"glibc by ldd", nil, ld("ldd (Ubuntu GLIBC 2.35-0ubuntu3.4) 2.35\nCopyright (C) 2022 Free Software Foundation\n"), "glibc"},
		{"glibc by ldd (GNU libc)", nil, ld("ldd (GNU libc) 2.31\n"), "glibc"},
		{"musl by loader file", []string{"/lib/ld-musl-mipsel.so.1"}, nil, "musl"},
		{"musl by alpine-release", []string{"/etc/alpine-release"}, nil, "musl"},
		{"musl by openwrt_release", []string{"/etc/openwrt_release"}, nil, "musl"},
		{"glibc by loader", []string{"/lib64/ld-linux-x86-64.so.2"}, nil, "glibc"},
		{"ldd wins over a stray musl loader", []string{"/lib/ld-musl-x86_64.so.1"}, ld("ldd (GNU libc) 2.31\n"), "glibc"},
		{"unknown", nil, nil, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := env("linux", "amd64", nil, c.files...)
			if c.mod != nil {
				c.mod(&e)
			}
			if got := DetectEnv(e).Libc; got != c.want {
				t.Errorf("libc=%q want %q", got, c.want)
			}
		})
	}
	if got := DetectEnv(env("windows", "amd64", nil, "/etc/alpine-release")).Libc; got != "" {
		t.Errorf("non-linux libc=%q", got)
	}
}

func TestCompatible(t *testing.T) {
	soft := Info{GOOS: "linux", GOARCH: "mipsle", Float: "softfloat", Libc: "musl"}
	hard := Info{GOOS: "linux", GOARCH: "mipsle", Float: "hardfloat", Libc: "glibc"}
	for _, c := range []struct {
		i       Info
		variant string
		ok      bool
	}{
		{soft, "softfloat", true},
		{soft, "hardfloat", false},
		{hard, "softfloat", true},
		{hard, "hardfloat", true},
		{soft, "sse2", false},
		{soft, "musl-full", true},
		{soft, "glibc", false},
		{hard, "glibc", true},
		{Info{GOOS: "linux", GOARCH: "amd64"}, "glibc", true}, // libc unknown: let the self-check decide
		{soft, "", true},
	} {
		err := c.i.Compatible(c.variant)
		if (err == nil) != c.ok {
			t.Errorf("%s variant %q: err=%v want ok=%v", c.i, c.variant, err, c.ok)
		}
	}
}

func TestDetectRuns(t *testing.T) {
	i := Detect()
	if i.GOOS == "" || i.GOARCH == "" || len(i.Keys()) == 0 {
		t.Fatalf("%+v", i)
	}
}
