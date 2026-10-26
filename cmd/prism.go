package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/W1nCwC/W1nCray/agent/bootstrap"
	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/prismapi"
	"github.com/W1nCwC/W1nCray/agent/prismsvc"
	"github.com/W1nCwC/W1nCray/agentd"
	"github.com/W1nCwC/W1nCray/kernel/install"
	"github.com/W1nCwC/W1nCray/kernel/manifest"
)

func init() {
	rootCmd.AddCommand(prismCmd())
}

// prismBinaryName is the installed file name of the Prism kernel.
const prismBinaryName = prismsvc.BinaryName

// prismKernelRun is the version self-check of the Prism kernel:
//
//	W1nCray-prism v0.1.0 (core 1.14.3, api 1)  ->  0.1.0
var prismKernelRun = manifest.Run{
	Binary:       prismBinaryName,
	VersionCmd:   []string{"version"},
	VersionRegex: `W1nCray-prism v?([0-9][0-9.]*)`,
}

// prismCmd is the parent of the local Prism kernel commands. The running agent
// brings the service up by itself once the kernel is installed and the panel
// has Prism nodes for this machine; these commands install the kernel on a
// machine that cannot download it (or before a release exists) and read its
// state.
func prismCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "prism",
		Short: "Manage the local Prism kernel (install --file, status, remove)",
	}
	c.AddCommand(prismInstallCmd(), prismStatusCmd(), prismRemoveCmd())

	return c
}

// prismLocalInstaller is the kernel-installer surface the --file path needs.
type prismLocalInstaller interface {
	InstallLocal(ctx context.Context, li install.LocalInstall) (driver.Installed, error)
}

func prismInstallCmd() *cobra.Command {
	var (
		file string
		sha  string
	)
	c := &cobra.Command{
		Use:   "install --file <binary|.gz> --sha256 <hex>",
		Short: "Install a Prism kernel build that is already on this machine",
		Long: "Install the Prism kernel from a local W1nCray-prism binary or its .gz release\n" +
			"asset. The sha256 pins the bytes (the release SHA256SUMS); the binary is run once\n" +
			"to check its version. The entry is the same one a panel install produces, so the\n" +
			"panel can list, upgrade and remove it. The agent starts the service by itself\n" +
			"when the panel has Prism nodes for this machine.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if file == "" || sha == "" {
				return fmt.Errorf("--file 与 --sha256 都是必需的")
			}
			path, err := findConfig()
			if err != nil {
				return err
			}
			cfg, err := agentd.LoadConfig(path)
			if err != nil {
				return err
			}
			kern, err := bootstrap.KernelInstaller(xrayKernelOptions(path, cfg))
			if err != nil {
				return err
			}

			return prismInstallLocal(cmd.Context(), kern, file, sha)
		},
	}
	c.Flags().StringVar(&file, "file", "", "the local W1nCray-prism binary or .gz asset")
	c.Flags().StringVar(&sha, "sha256", "", "hex sha256 of --file")

	return c
}

// prismInstallLocal installs a local build into the kernel directory. It is
// separate from the command so it can be tested with a fake installer.
func prismInstallLocal(ctx context.Context, kern prismLocalInstaller, file, sha string) error {
	inst, err := kern.InstallLocal(ctx, install.LocalInstall{
		Name:          prismapi.KernelName,
		Archive:       file,
		ArchiveSHA256: sha,
		To:            prismBinaryName,
		Run:           prismKernelRun,
	})
	if err != nil {
		return err
	}
	fmt.Printf("已安装 Prism 内核 %s（%s）\n", inst.Version, inst.Path)

	return nil
}

func prismStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show the local Prism kernel's own status",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := prismapi.New("unix:" + prismsvc.SocketPath())
			if err != nil {
				return err
			}
			st, err := client.Status(cmd.Context())
			if err != nil {
				return fmt.Errorf("Prism 内核没有应答（未安装或未运行）: %w", err)
			}
			hash := "-"
			if st.ConfigHash != nil {
				hash = *st.ConfigHash
			}
			fmt.Printf("W1nCray-prism v%s（core %s） state=%s config=%s\n", st.Version, st.Core, st.State, hash)
			for _, in := range st.Inbounds {
				fmt.Printf("  %-24s %-10s users=%d conns=%d\n", in.Tag, in.Type, in.Users, in.Conns)
			}

			return nil
		},
	}
}

// prismRemover is the service-manager surface `prism remove` needs
// (*prismsvc.Manager implements it).
type prismRemover interface {
	Backend() string
	Remove(ctx context.Context) error
}

// noKernels is the kernel lookup of a manager that only removes a service
// definition: it never needs the installed binary.
type noKernels struct{}

func (noKernels) Current(string) (driver.Installed, error) {
	return driver.Installed{}, prismsvc.ErrNotInstalled
}

func prismRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove",
		Short: "Stop the Prism kernel service and remove its service definition",
		Long: "Stop the W1nCray-prism service, take it out of the boot sequence and delete its\n" +
			"unit or init script. The installed kernel file is kept. A machine whose kernel\n" +
			"runs under the agent (no systemd/OpenRC/procd service) has nothing to remove here.\n" +
			"While the machine still has Prism nodes, a running agent creates the service again\n" +
			"within a minute: disable or unbind the nodes first (or stop the agent).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// No supervisor: only a real service backend can be detected.
			mgr, err := prismsvc.New(prismsvc.Options{Kernels: noKernels{}})
			if err != nil {
				fmt.Println("没有 Prism 服务需要移除（内核由 agent 托管或未安装服务）")
				return nil
			}

			return prismRemove(cmd.Context(), mgr)
		},
	}
}

// prismRemove is separate from the command so it can be tested.
func prismRemove(ctx context.Context, mgr prismRemover) error {
	if mgr.Backend() == "" {
		fmt.Println("没有 Prism 服务需要移除（此机器的 init 系统不受支持）")
		return nil
	}
	if err := mgr.Remove(ctx); err != nil {
		return fmt.Errorf("移除 Prism 服务: %w", err)
	}
	fmt.Println("已移除 Prism 服务（内核文件保留）")
	fmt.Println("提示：机器上仍有 Prism 节点时，运行中的 agent 会重新创建该服务；请先停用或解绑节点（或先停止 agent）")

	return nil
}
