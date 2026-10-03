package cmd

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/W1nCwC/W1nCray/panel"
)

var checkOnline bool

func init() {
	c := &cobra.Command{
		Use:   "check",
		Short: "Validate the config (and with --online, the panel nodes) without serving traffic",
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := findConfig()
			if err != nil {
				return err
			}
			setAssetLocation(path)
			return panel.Check(path, checkOnline, os.Stdout)
		},
	}
	c.Flags().BoolVar(&checkOnline, "online", false, "also fetch every node from the panel and build its inbound")
	rootCmd.AddCommand(c)
}
