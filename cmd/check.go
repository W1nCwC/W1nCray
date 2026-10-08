package cmd

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/W1nCwC/W1nCray/agentd"
)

var checkOnline bool

func init() {
	c := &cobra.Command{
		Use:   "check",
		Short: "Validate the agent config without serving traffic",
		Long: "Validate the agent configuration (agent.yml or the Agent: block of config.yml).\n" +
			"The Xray section is checked by the kernel program: run\n" +
			"`W1nCray-xray check -c <config.yml>` for that.",
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := findConfig()
			if err != nil {
				return err
			}
			return agentd.Check(path, checkOnline, os.Stdout)
		},
	}
	c.Flags().BoolVar(&checkOnline, "online", false, "also fetch the panel-served kernel manifest")
	rootCmd.AddCommand(c)
}
