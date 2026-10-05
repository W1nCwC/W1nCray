package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/W1nCwC/W1nCray/agent/bootstrap"
	"github.com/W1nCwC/W1nCray/panel"
)

var agentApplyFile string

func init() {
	c := &cobra.Command{
		Use:   "agent-apply",
		Short: "Apply a desired-state JSON file once and print the report",
		Long: "Apply a desired-state JSON file once and print the resulting report as JSON.\n" +
			"Only the external engines (gost, frp, realm) can run without a panel: the\n" +
			"builtin xray engine needs the running instance and is not registered here.\n" +
			"Kernels that were started keep running after the command exits.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if agentApplyFile == "" {
				return fmt.Errorf("a desired-state file is required (-f desired.json)")
			}
			path, err := findConfig()
			if err != nil {
				return err
			}
			setAssetLocation(path)
			cfg, err := panel.LoadConfig(path)
			if err != nil {
				return err
			}
			if cfg.Agent == nil || !cfg.Agent.Enabled {
				return fmt.Errorf("config %s has no enabled Agent section", path)
			}
			rt, err := bootstrap.Boot(bootstrap.Options{
				StateDir:         cfg.Agent.StateDir,
				KernelsDir:       cfg.Agent.KernelsDir,
				ManifestPath:     cfg.Agent.ManifestPath,
				ManifestKeysPath: cfg.Agent.ManifestKeysPath,
				Policy:           cfg.Agent.PolicySpec(),
				Log:              log.StandardLogger(),
			}, nil)
			if err != nil {
				return err
			}
			rep, applyErr := rt.ApplyFile(agentApplyFile)
			// The report is secret-free by construction (the reconciler scrubs
			// every secret before it is stored). Print it even on failure.
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(rep); err != nil && applyErr == nil {
				return err
			}
			return applyErr
		},
	}
	c.Flags().StringVarP(&agentApplyFile, "file", "f", "", "desired-state JSON file to apply")
	rootCmd.AddCommand(c)
}
