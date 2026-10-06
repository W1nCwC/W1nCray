package cmd

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/W1nCwC/W1nCray/agent/selfupdate"
)

// respawnCmd is the hidden watchdog a committed self_update starts. It runs
// from a copy of the previous, known-good binary, waits for the agent that
// committed the update to exit, and rolls the update back when the new binary
// never comes up. It never starts the agent itself: the service manager
// (Restart=always / supervise-daemon / procd respawn) does. It is not in --help
// and is never run by hand.
func init() {
	c := &cobra.Command{
		Use:                selfupdate.HelperCommand + " [-parent PID] [-state DIR] [-exe EXE] [-lock FILE] [-unit UNIT] [-- argv...]",
		Short:              "internal: self-update watchdog",
		Hidden:             true,
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			h, err := selfupdate.ParseHelperArgs(args)
			if err != nil {
				return err
			}
			if err := selfupdate.RunHelper(context.Background(), h, log.StandardLogger()); err != nil {
				return fmt.Errorf("self-update watchdog: %w", err)
			}
			return nil
		},
	}
	rootCmd.AddCommand(c)
}
