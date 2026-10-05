package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	xcore "github.com/xtls/xray-core/core"

	"github.com/W1nCwC/W1nCray/common/cert"
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

func showVersion() {
	fmt.Printf("W1nCray %s (Xray-core %s, %s)\n", version, xcore.Version(), cert.BuildFlavor)
}
