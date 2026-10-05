package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/W1nCwC/W1nCray/agent/bootstrap"
	"github.com/W1nCwC/W1nCray/panel"
)

var agentApplyFile string

// acquireLock takes the single-instance lock of a config file. It is a variable
// so tests can observe and fail it; production code never changes it.
var acquireLock = acquireInstanceLock

func init() {
	// The panel link reports the build version; the version string lives here.
	panel.AgentVersion = version

	c := &cobra.Command{
		Use:   "agent-apply",
		Short: "Apply a desired-state JSON file once and print the report",
		Long: "Apply a desired-state JSON file once and print the resulting report as JSON.\n" +
			"Only the external engines (gost, frp, realm) can run without a panel: the\n" +
			"builtin xray engine needs the running instance and is not registered here.\n" +
			"Kernels that were started keep running after the command exits.\n" +
			"The command takes the same single-instance lock as the service: stop the\n" +
			"service first if it runs with this config.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if agentApplyFile == "" {
				return fmt.Errorf("a desired-state file is required (-f desired.json)")
			}
			path, err := findConfig()
			if err != nil {
				return err
			}
			setAssetLocation(path)
			return runAgentApply(path, agentApplyFile, os.Stdout)
		},
	}
	c.Flags().StringVarP(&agentApplyFile, "file", "f", "", "desired-state JSON file to apply")
	rootCmd.AddCommand(c)
}

// runAgentApply applies desiredFile once with the agent configured in
// configPath and prints the report to out.
//
// It holds the config's single-instance lock for the whole run, like the
// service does: both would otherwise drive the same state directory (state
// files, the kernels' pid files and ports) and corrupt each other.
func runAgentApply(configPath, desiredFile string, out io.Writer) error {
	lock, err := acquireLock(configPath)
	if err != nil {
		return fmt.Errorf("agent-apply cannot run next to the service using this config (stop the service first): %w", err)
	}
	defer lock.release()

	cfg, err := panel.LoadConfig(configPath)
	if err != nil {
		return err
	}
	if cfg.Agent == nil || !cfg.Agent.Enabled {
		return fmt.Errorf("config %s has no enabled Agent section", configPath)
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
	rep, applyErr := rt.ApplyFile(desiredFile)
	// The report is secret-free by construction (the reconciler scrubs
	// every secret before it is stored). Print it even on failure.
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rep); err != nil && applyErr == nil {
		return err
	}
	return applyErr
}
