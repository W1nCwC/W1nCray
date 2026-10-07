// The `W1nCray xray` command is the local operations entry point of the Xray
// kernel service (PLAN v11 §D). It drives the same agent/xraysvc manager the
// agent uses, so the panel and an operator on the machine cannot diverge: one
// service definition, one set of paths, one health check.
//
// It is for local operations. It does not take the agent's single-instance lock
// (an operator must be able to ask for the status while the agent runs), so do
// not run install/remove while the agent is installing a kernel at the same
// time.
package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	log "github.com/sirupsen/logrus"

	"github.com/W1nCwC/W1nCray/agent/bootstrap"
	"github.com/W1nCwC/W1nCray/agent/supervisor"
	"github.com/W1nCwC/W1nCray/agent/xraysvc"
	"github.com/W1nCwC/W1nCray/agentd"
)

func init() {
	rootCmd.AddCommand(xrayCmd())
}

// xrayCmd is the parent command; each subcommand builds the manager and calls
// one method on it.
func xrayCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "xray",
		Short: "Manage the local Xray kernel service (status, start, stop, restart, install, remove)",
		Long: "Manage the local Xray kernel (the W1nCray-xray program) as a service:\n" +
			"systemd, OpenRC, procd, or the agent supervisor when none of them exists.\n" +
			"Install downloads the signed manifest's kernel; Remove keeps config.yml and\n" +
			"the managed files.",
	}
	for _, sub := range []*cobra.Command{
		xrayStatusCmd(),
		xrayStartCmd(),
		xrayStopCmd(),
		xrayRestartCmd(),
		xrayInstallCmd(),
		xrayRemoveCmd(),
	} {
		c.AddCommand(sub)
	}
	return c
}

// xrayManager builds the service manager from the machine's configuration.
func xrayManager() (*xraysvc.Manager, error) {
	path, err := findConfig()
	if err != nil {
		return nil, err
	}
	cfg, err := agentd.LoadConfig(path)
	if err != nil {
		return nil, err
	}
	stateDir, kernelsDir := "", ""
	manifest, keys := "", ""
	if a := cfg.Agent; a != nil {
		stateDir, kernelsDir = a.StateDir, a.KernelsDir
		manifest, keys = a.ManifestPath, a.ManifestKeysPath
	}
	if stateDir == "" {
		stateDir = filepath.Join(filepath.Dir(path), "state")
	}
	if kernelsDir == "" {
		kernelsDir = filepath.Join(stateDir, "kernels")
	}
	o := bootstrap.Options{
		StateDir:         stateDir,
		KernelsDir:       kernelsDir,
		ManifestPath:     manifest,
		ManifestKeysPath: keys,
		AgentVersion:     agentd.AgentVersion,
		XrayConfigPath:   path,
		Log:              log.StandardLogger(),
	}
	kern, err := bootstrap.KernelInstaller(o)
	if err != nil {
		return nil, err
	}
	sup := supervisor.New(supervisor.Options{Log: o.Log, PIDDir: filepath.Join(stateDir, "pid")})
	mgr, _, err := bootstrap.XrayManager(o, kern, sup)
	return mgr, err
}

func xrayStatusCmd() *cobra.Command {
	var asJSON bool
	c := &cobra.Command{
		Use:   "status",
		Short: "Print the Xray kernel service status",
		RunE: func(cmd *cobra.Command, args []string) error {
			mgr, err := xrayManager()
			if err != nil {
				return err
			}
			st, err := mgr.Status(cmd.Context())
			if err != nil {
				return err
			}
			if asJSON {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(st)
			}
			fmt.Printf("%s: backend=%s state=%s managed_by=%s", xraysvc.ServiceName, st.Backend, st.State, st.ManagedBy)
			if st.Version != "" {
				fmt.Printf(" version=%s", st.Version)
			}
			if st.Path != "" {
				fmt.Printf(" path=%s", st.Path)
			}
			if st.UnitPath != "" {
				fmt.Printf(" unit=%s", st.UnitPath)
			}
			fmt.Println()
			if st.Error != "" {
				fmt.Printf("error: %s\n", st.Error)
			}
			return nil
		},
	}
	c.Flags().BoolVar(&asJSON, "json", false, "print the status as JSON")
	return c
}

func xrayStartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "Start the Xray kernel service (the kernel must be installed)",
		RunE: func(cmd *cobra.Command, args []string) error {
			mgr, err := xrayManager()
			if err != nil {
				return err
			}
			if err := mgr.Start(cmd.Context()); err != nil {
				return err
			}
			fmt.Printf("%s 已启动\n", xraysvc.ServiceName)
			return nil
		},
	}
}

func xrayStopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "Stop the Xray kernel service",
		RunE: func(cmd *cobra.Command, args []string) error {
			mgr, err := xrayManager()
			if err != nil {
				return err
			}
			if err := mgr.Stop(cmd.Context()); err != nil {
				return err
			}
			fmt.Printf("%s 已停止\n", xraysvc.ServiceName)
			return nil
		},
	}
}

func xrayRestartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "restart",
		Short: "Restart the Xray kernel service",
		RunE: func(cmd *cobra.Command, args []string) error {
			mgr, err := xrayManager()
			if err != nil {
				return err
			}
			if err := mgr.Restart(cmd.Context()); err != nil {
				return err
			}
			fmt.Printf("%s 已重启\n", xraysvc.ServiceName)
			return nil
		},
	}
}

func xrayInstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "install [version]",
		Short: "Install the Xray kernel (newest manifest version by default) and start its service",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			mgr, err := xrayManager()
			if err != nil {
				return err
			}
			version := ""
			if len(args) == 1 {
				version = args[0]
			}
			if err := mgr.Install(cmd.Context(), version); err != nil {
				return err
			}
			st, _ := mgr.Status(cmd.Context())
			fmt.Printf("%s 已安装并运行（版本 %s，backend %s）\n", xraysvc.ServiceName, st.Version, st.Backend)
			return nil
		},
	}
}

func xrayRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove",
		Short: "Stop and remove the Xray kernel service and files (config.yml is kept)",
		RunE: func(cmd *cobra.Command, args []string) error {
			mgr, err := xrayManager()
			if err != nil {
				return err
			}
			if err := mgr.Remove(cmd.Context()); err != nil {
				return err
			}
			fmt.Printf("%s 已卸载（配置与受管文件保留）\n", xraysvc.ServiceName)
			return nil
		},
	}
}
