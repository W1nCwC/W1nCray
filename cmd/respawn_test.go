package cmd

import (
	"testing"

	"github.com/spf13/cobra"

	"github.com/W1nCwC/W1nCray/agent/selfupdate"
)

// findRespawn returns the hidden helper command.
func findRespawn(t *testing.T) *cobra.Command {
	t.Helper()
	for _, c := range rootCmd.Commands() {
		if c.Name() == selfupdate.HelperCommand {
			return c
		}
	}
	t.Fatalf("%s is not registered", selfupdate.HelperCommand)
	return nil
}

// TestRespawnCommandIsHidden keeps the watchdog out of --help: it is an
// internal re-exec of the agent's previous binary, not something an operator
// runs.
func TestRespawnCommandIsHidden(t *testing.T) {
	c := findRespawn(t)
	if !c.Hidden {
		t.Error("the self-update watchdog must be hidden")
	}
	if !c.DisableFlagParsing {
		t.Error("the self-update watchdog must parse its own argv (the agent's own flags follow --)")
	}
}

// TestRespawnCommandRefusesBadArguments covers the helper's argument contract:
// a malformed or incomplete command line fails instead of starting anything.
func TestRespawnCommandRefusesBadArguments(t *testing.T) {
	c := findRespawn(t)
	for _, args := range [][]string{
		{"-bogus", "1", "--"},
		{"-parent", "not-a-number", "--"},
		{"-parent", "0", "-state", "", "-exe", "", "--"},
	} {
		if err := c.RunE(c, args); err == nil {
			t.Errorf("RunE(%v) = nil, want an error", args)
		}
	}
}
