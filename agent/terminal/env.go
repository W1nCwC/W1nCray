package terminal

import (
	"os"
	"os/user"
	"strings"
)

// safeEnvKeys is the allowlist of environment variables a terminal session may
// inherit. It is an allowlist on purpose: a blocklist would leak every variable
// nobody thought of, and the agent's own process environment holds the machine
// token (W1NCRAY_TOKEN), the Agent.* configuration values and, on some
// platforms, injection surfaces like LD_PRELOAD.
//
// Everything else is dropped, including LD_PRELOAD, LD_LIBRARY_PATH, LD_AUDIT,
// PYTHONPATH, NODE_OPTIONS, BASH_ENV, ENV, anything whose name contains "TOKEN"
// or "SECRET", and every "Agent.*" value.
var safeEnvKeys = map[string]bool{
	"TERM":     true,
	"LANG":     true,
	"LC_ALL":   true,
	"LC_CTYPE": true,
	"PATH":     true,
	"HOME":     true,
	"USER":     true,
	"LOGNAME":  true,
	"SHELL":    true,
	"TZ":       true,
	"PWD":      true,
}

// DefaultPath is the PATH a sanitised session falls back to when the agent's
// own PATH is empty or unsafe. It covers the usual Unix layouts; OpenWrt's
// /bin/busybox lives in /bin, which is last.
const DefaultPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// SanitizeEnv returns the minimal environment a shell is started with. It never
// puts the machine token or any Agent.* value into the child: only the fixed
// allowlist above survives, and the caller cannot add to it.
//
// The signature takes no argument on purpose: a caller that could pass extra
// variables could reintroduce exactly what this function exists to remove.
func SanitizeEnv() []string {
	return sanitizeEnv(os.Environ())
}

// sanitizeEnv filters an environment slice through the allowlist. It is the
// testable core of SanitizeEnv; it is unexported because nothing outside this
// package may decide what a shell sees.
func sanitizeEnv(environ []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(safeEnvKeys))
	for _, kv := range environ {
		i := strings.IndexByte(kv, '=')
		if i <= 0 {
			continue
		}
		name := kv[:i]
		if !safeEnvKeys[name] || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, kv)
	}
	return fillDefaults(out, seen)
}

// fillDefaults completes the environment so a shell always has a usable TERM,
// PATH and HOME, whatever the agent's own environment looked like. The values
// are fixed here, never taken from a variable the caller controls.
func fillDefaults(env []string, seen map[string]bool) []string {
	if !seen["TERM"] {
		env = append(env, "TERM=xterm-256color")
	}
	if !seen["LANG"] && !seen["LC_ALL"] {
		env = append(env, "LANG=C.UTF-8")
	}
	if !seen["PATH"] {
		env = append(env, "PATH="+DefaultPath)
	}
	if !seen["HOME"] {
		env = append(env, "HOME="+defaultHome())
	}
	return env
}

// defaultHome is the home directory a session falls back to. It comes from the
// account database, not from $HOME, so a poisoned variable cannot choose it.
func defaultHome() string {
	if u, err := user.Current(); err == nil && u.HomeDir != "" && !strings.ContainsAny(u.HomeDir, "\x00") {
		return u.HomeDir
	}
	return "/"
}

// envValue returns the value of a variable in an environment slice (the last
// occurrence wins, like exec does).
func envValue(env []string, name string) (string, bool) {
	prefix := name + "="
	for i := len(env) - 1; i >= 0; i-- {
		if strings.HasPrefix(env[i], prefix) {
			return env[i][len(prefix):], true
		}
	}
	return "", false
}
