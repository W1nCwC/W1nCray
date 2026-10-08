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
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/W1nCwC/W1nCray/agent/bootstrap"
	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/kernelx"
	"github.com/W1nCwC/W1nCray/agent/selinux"
	"github.com/W1nCwC/W1nCray/agent/supervisor"
	"github.com/W1nCwC/W1nCray/agent/xrayapi"
	"github.com/W1nCwC/W1nCray/agent/xraysvc"
	"github.com/W1nCwC/W1nCray/agentd"
	"github.com/W1nCwC/W1nCray/kernel/install"
	"github.com/W1nCwC/W1nCray/kernel/manifest"
)

// xrayBinaryName is the installed file name of the Xray kernel, and the name
// its manifest entry uses (run.binary in tools/manifestgen/examples/v11.yaml).
const xrayBinaryName = "W1nCray-xray"

// xrayKernelRun is the version self-check of the Xray kernel. It mirrors the
// manifest entry exactly, so a local install (--file) and a manifest install
// agree on what version the binary reports:
//
//	W1nCray-xray v0.6.0 (Xray-core 26.3.27)  ->  0.6.0
var xrayKernelRun = manifest.Run{
	Binary:       xrayBinaryName,
	VersionCmd:   []string{"version"},
	VersionRegex: `W1nCray-xray v?([0-9][0-9.]*)`,
}

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

// xrayKernelOptions builds the bootstrap options of the local xray command
// from the machine's configuration. It is separate from xrayManager so the
// wiring of the local kernel-source switch (Kernels.AllowHTTP) can be tested
// without a running service manager.
func xrayKernelOptions(path string, cfg *agentd.Config) bootstrap.Options {
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
	return bootstrap.Options{
		StateDir:         stateDir,
		KernelsDir:       kernelsDir,
		ManifestPath:     manifest,
		ManifestKeysPath: keys,
		AgentVersion:     agentd.AgentVersion,
		// The local kernel-source switch (Kernels.AllowHTTP, D-M1): the same
		// value the service uses, so `W1nCray xray install` can reach the same
		// mirror the agent would.
		AllowHTTP:      agentd.KernelAllowHTTP(cfg),
		XrayConfigPath: path,
		Labeler:        selinux.New(selinux.Options{Log: log.StandardLogger()}),
		Log:            log.StandardLogger(),
	}
}

// xrayManager builds the service manager and the kernel installer from the
// machine's configuration. The installer is returned too: the local install
// path (--file) needs it, and it is the same object the manager uses, so the
// kernel directory still has exactly one owner.
func xrayManager() (*xraysvc.Manager, *kernelx.Ensurer, error) {
	path, err := findConfig()
	if err != nil {
		return nil, nil, err
	}
	cfg, err := agentd.LoadConfig(path)
	if err != nil {
		return nil, nil, err
	}
	o := xrayKernelOptions(path, cfg)
	kern, err := bootstrap.KernelInstaller(o)
	if err != nil {
		return nil, nil, err
	}
	sup := supervisor.New(supervisor.Options{Log: o.Log, PIDDir: filepath.Join(o.StateDir, "pid"), Labeler: o.Labeler})
	mgr, _, err := bootstrap.XrayManager(o, kern, sup)
	return mgr, kern, err
}

func xrayStatusCmd() *cobra.Command {
	var asJSON bool
	c := &cobra.Command{
		Use:   "status",
		Short: "Print the Xray kernel service status",
		RunE: func(cmd *cobra.Command, args []string) error {
			mgr, _, err := xrayManager()
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
			mgr, _, err := xrayManager()
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
			mgr, _, err := xrayManager()
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
			mgr, _, err := xrayManager()
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

// xrayLocalInstaller is the kernel-installer surface the --file path needs.
// *kernelx.Ensurer implements it; the interface exists so the command's local
// install can be tested without a running service manager.
type xrayLocalInstaller interface {
	InstallLocal(ctx context.Context, li install.LocalInstall) (driver.Installed, error)
}

func xrayInstallCmd() *cobra.Command {
	var (
		file string
		sha  string
	)
	c := &cobra.Command{
		Use:   "install [version]",
		Short: "Install the Xray kernel (newest manifest version by default) and start its service",
		Long: "Install the Xray kernel and start its service.\n" +
			"Without flags the newest version of the signed manifest is installed.\n" +
			"With --file (and the required --sha256) a build already on this machine is\n" +
			"installed instead: the file may be a W1nCray-xray binary or its .gz release\n" +
			"asset. This is what install.sh uses on machines that cannot reach the panel,\n" +
			"and it produces exactly the same kernel directory entry as a manifest install,\n" +
			"so list, upgrade, rollback and remove all recognise it.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Validate the flag combination before touching any configuration.
			switch {
			case file != "" && len(args) == 1:
				return fmt.Errorf("--file 与版本号参数不能同时使用（本地安装的版本由程序自身报告）")
			case file != "" && sha == "":
				return fmt.Errorf("--file 需要 --sha256 <hex>（发行版 SHA256SUMS 里的校验值）")
			case file == "" && sha != "":
				return fmt.Errorf("--sha256 只能与 --file 一起使用")
			}
			mgr, kern, err := xrayManager()
			if err != nil {
				return err
			}
			if file != "" {
				if err := xrayInstallLocal(cmd.Context(), kern, file, sha); err != nil {
					return err
				}
				// The kernel is in place; the service manager points the
				// service at it and brings it up. A service that was already
				// running another version is restarted here (activate decides
				// from the changed unit and the running kernel's version), so
				// the old process cannot keep serving behind the new pointer
				// (R1-5).
				if err := mgr.Start(cmd.Context()); err != nil {
					return fmt.Errorf("%w（内核已安装，可执行 `W1nCray xray start` 重试）", err)
				}
				st, _ := mgr.Status(cmd.Context())
				fmt.Printf("%s 已安装并运行（版本 %s，backend %s）\n", xraysvc.ServiceName, st.Version, st.Backend)
				return nil
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
	c.Flags().StringVar(&file, "file", "", "install this local W1nCray-xray binary or .gz asset instead of a manifest version")
	c.Flags().StringVar(&sha, "sha256", "", "hex sha256 of --file (required with --file)")
	return c
}

// xrayInstallLocal installs a local build into the kernel directory. It is
// separate from the command so it can be tested with a fake installer.
func xrayInstallLocal(ctx context.Context, kern xrayLocalInstaller, file, sha string) error {
	inst, err := kern.InstallLocal(ctx, install.LocalInstall{
		Name:          xrayapi.KernelName,
		Archive:       file,
		ArchiveSHA256: sha,
		To:            xrayBinaryName,
		Run:           xrayKernelRun,
	})
	if err != nil {
		return err
	}
	fmt.Printf("已安装 Xray 内核 %s（%s）\n", inst.Version, inst.Path)
	return nil
}

func xrayRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove",
		Short: "Stop and remove the Xray kernel service and files (config.yml is kept)",
		RunE: func(cmd *cobra.Command, args []string) error {
			mgr, _, err := xrayManager()
			if err != nil {
				return err
			}
			removed, err := mgr.Remove(cmd.Context())
			if err != nil {
				return err
			}
			if !removed {
				fmt.Printf("%s 本就未安装（无需卸载）\n", xraysvc.ServiceName)
				return nil
			}
			fmt.Printf("%s 已卸载（配置与受管文件保留）\n", xraysvc.ServiceName)
			return nil
		},
	}
}
