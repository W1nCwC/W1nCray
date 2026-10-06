package terminal

import (
	"strings"
	"testing"
)

// TestSanitizeEnvIsAnAllowlist covers WP-G6 acceptance 5 at the unit level: the
// environment a shell is started with must not contain the machine token, any
// Agent.* value, or an injection surface.
func TestSanitizeEnvIsAnAllowlist(t *testing.T) {
	hostile := []string{
		"PATH=/usr/bin",
		"TERM=xterm",
		"HOME=/root",
		"W1NCRAY_TOKEN=super-secret-machine-token",
		"AGENT_PANEL_TOKEN=another-secret",
		"Agent.Panel.Token=yet-another-secret",
		"AGENT_PANEL_URL=https://panel.example.com",
		"LD_PRELOAD=/tmp/evil.so",
		"LD_LIBRARY_PATH=/tmp/evil",
		"LD_AUDIT=/tmp/audit.so",
		"BASH_ENV=/tmp/profile",
		"ENV=/tmp/profile",
		"NODE_OPTIONS=--require /tmp/evil.js",
		"PYTHONPATH=/tmp/evil",
		"AWS_SECRET_ACCESS_KEY=aws-secret",
		"GITHUB_TOKEN=gh-secret",
		"MY_PASSWORD=hunter2",
		"W1NCRAY_MACHINE_TOKEN=tok",
		"EMPTY_NAME=",
		"=novalue",
		"NOEQUALS",
	}
	env := sanitizeEnv(hostile)
	joined := strings.Join(env, "\n")

	for _, banned := range []string{
		"super-secret-machine-token", "another-secret", "yet-another-secret",
		"LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "BASH_ENV", "NODE_OPTIONS",
		"PYTHONPATH", "aws-secret", "gh-secret", "hunter2", "W1NCRAY_TOKEN",
		"AGENT_PANEL", "Agent.Panel",
	} {
		if strings.Contains(joined, banned) {
			t.Errorf("sanitised environment still contains %q:\n%s", banned, joined)
		}
	}
	// The allowlisted variables survive.
	for _, want := range []string{"PATH=/usr/bin", "TERM=xterm", "HOME=/root"} {
		if !strings.Contains(joined, want) {
			t.Errorf("sanitised environment lost %q:\n%s", want, joined)
		}
	}
	// Every key that survived must be on the allowlist: this is what makes the
	// function an allowlist rather than a blocklist that misses the next
	// injection surface.
	for _, kv := range env {
		name, _, ok := strings.Cut(kv, "=")
		if !ok || name == "" {
			t.Errorf("malformed entry %q", kv)
			continue
		}
		if !safeEnvKeys[name] {
			t.Errorf("variable %q is not on the allowlist but survived", name)
		}
	}
}

// TestSanitizeEnvFillsDefaults covers the other half: a shell always gets a
// usable TERM/PATH/HOME/LANG, and the fallbacks never come from the (possibly
// poisoned) host environment.
func TestSanitizeEnvFillsDefaults(t *testing.T) {
	env := sanitizeEnv(nil)
	for _, want := range []string{"TERM=", "PATH=", "HOME=", "LANG="} {
		if v, ok := envValue(env, strings.TrimSuffix(want, "=")); !ok || v == "" {
			t.Errorf("default environment is missing %s: %v", want, env)
		}
	}
	if v, _ := envValue(env, "PATH"); v != DefaultPath {
		t.Errorf("PATH default = %q, want %q", v, DefaultPath)
	}
	if v, _ := envValue(env, "TERM"); v != "xterm-256color" {
		t.Errorf("TERM default = %q", v)
	}
}

// TestSanitizeEnvKeepsAnExplicitTerm checks that a value the allowlist permits
// is not overwritten by a default.
func TestSanitizeEnvKeepsAnExplicitTerm(t *testing.T) {
	env := sanitizeEnv([]string{"TERM=vt100", "PATH=/bin"})
	if v, _ := envValue(env, "TERM"); v != "vt100" {
		t.Errorf("TERM = %q, want vt100", v)
	}
	if v, _ := envValue(env, "PATH"); v != "/bin" {
		t.Errorf("PATH = %q, want /bin", v)
	}
}

// TestSanitizeEnvIgnoresMalformedEntries makes sure one broken variable cannot
// make the whole exec fail: entries without a name or without an "=" are
// dropped, and the defaults are still filled in.
func TestSanitizeEnvIgnoresMalformedEntries(t *testing.T) {
	env := sanitizeEnv([]string{"=novalue", "NOEQUALS", "LANG=C"})
	for _, kv := range env {
		if strings.HasPrefix(kv, "=") || !strings.Contains(kv, "=") {
			t.Errorf("malformed entry survived: %q", kv)
		}
	}
	if v, _ := envValue(env, "LANG"); v != "C" {
		t.Errorf("LANG = %q, want C", v)
	}
	// The default TERM is filled back in.
	if v, _ := envValue(env, "TERM"); v != "xterm-256color" {
		t.Errorf("TERM = %q, want the default", v)
	}
}

// TestSanitizeEnvReadsTheProcessEnvironment covers the exported entry point:
// the agent's own environment is filtered, not passed through.
func TestSanitizeEnvReadsTheProcessEnvironment(t *testing.T) {
	t.Setenv("W1NCRAY_TOKEN", "process-secret")
	t.Setenv("LD_PRELOAD", "/tmp/evil.so")
	env := SanitizeEnv()
	joined := strings.Join(env, "\n")
	for _, banned := range []string{"process-secret", "LD_PRELOAD"} {
		if strings.Contains(joined, banned) {
			t.Errorf("SanitizeEnv leaked %q: %v", banned, env)
		}
	}
}
