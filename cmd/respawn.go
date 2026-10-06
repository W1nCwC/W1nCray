package cmd

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/W1nCwC/W1nCray/agent/selfupdate"
)

// respawnCmd is the hidden helper a committed self_update starts: it waits for
// the agent that spawned it to exit, runs the new binary, and rolls back to
// exe.old when the new binary never stays alive. It is not in --help and is
// never run by hand.
func init() {
	c := &cobra.Command{
		Use:                selfupdate.HelperCommand + " [-parent PID] [-state DIR] [-exe EXE] [-- argv...]",
		Short:              "internal: self-update respawn helper",
		Hidden:             true,
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			h, err := selfupdate.ParseHelperArgs(args)
			if err != nil {
				return err
			}
			if err := selfupdate.RunHelper(context.Background(), h, log.StandardLogger()); err != nil {
				return fmt.Errorf("respawn helper: %w", err)
			}
			return nil
		},
	}
	rootCmd.AddCommand(c)
}
