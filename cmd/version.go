package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/W1nCwC/W1nCray/common/certcfg"
)

// Set at build time with -ldflags "-X github.com/W1nCwC/W1nCray/cmd.version=...".
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

// showVersion prints the agent version. The Xray-core version is printed by
// the kernel program (W1nCray-xray version): the agent does not link Xray-core.
func showVersion() {
	fmt.Printf("W1nCray %s (agent, %s)\n", version, certcfg.BuildFlavor)
}
