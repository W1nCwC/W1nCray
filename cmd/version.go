package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/W1nCwC/W1nCray/common/certcfg"
)

// Set at build time with -ldflags "-X github.com/W1nCwC/W1nCray/cmd.version=...".
// The default is the next release in development (0.8.0-dev): the manifest
// version_regex "W1nCray v?([0-9][0-9.]*)" parses it as 0.8.0, so a manifest
// entry built from this tree self-checks against the right version.
var version = "0.8.0-dev"

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
