// This file holds the one policy that agent/supervisor/noshell_test.go
// enforces: the closed list of packages under agent/ that may start a shell.
//
// It lives in a non-test file on purpose. The whitelist is part of the agent's
// security model, not a test fixture: agent/terminal/noshell_allow_test.go
// imports it to assert that the exception is real, that nothing outside it
// starts a shell, and that every entry is recorded in docs/AGENT.md. A test-only
// variable could not be imported, and a whitelist nothing can read is a
// whitelist nobody reviews.

package supervisor

// AllowedShellPackages is the closed list of packages under agent/ that may
// start a shell. The key is the package path relative to the repository root,
// the value is the reason it is exempt; the reason must name docs/AGENT.md,
// where the security-model change is recorded (design section 3.8).
//
// Adding an entry is a conscious change to the agent's security model: it must
// come with the matching paragraph in docs/AGENT.md and an update to
// agent/terminal/noshell_allow_test.go, which pins the list to exactly one
// package.
var AllowedShellPackages = map[string]string{
	"agent/terminal": "D8: the interactive terminal is an intentional capability behind a local switch (Terminal.Enabled, default on, installer flag --noterminal); it is the only package that starts a shell, and it is bound by agent/terminal/noshell_allow_test.go and the security-model record in docs/AGENT.md",
}
