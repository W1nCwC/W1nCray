package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	xcore "github.com/xtls/xray-core/core"
)

// Set at build time with -ldflags "-X w1ncray/cmd.version=...".
var version = "dev"

func init() {
	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Run: func(cmd *cobra.Command, args []string) {
			showVersion()
		},
	})
}

func showVersion() {
	fmt.Printf("W1nCray %s (Xray-core %s)\n", version, xcore.Version())
}
