package cmd

import (
	"context"
	"fmt"
	"io"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/W1nCwC/W1nCray/agent/porthop"
	"github.com/W1nCwC/W1nCray/agentd"
)

func init() {
	rootCmd.AddCommand(porthopCmd())
}

// porthopCmd is the parent of the local Hysteria port-hop commands. The running
// agent installs and repairs the redirect by itself; these commands read it
// and take it away (the uninstaller calls clear).
func porthopCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "porthop",
		Short: "Inspect or remove the local Hysteria port-hop firewall rules (status, clear)",
	}
	c.AddCommand(porthopStatusCmd(), porthopClearCmd())

	return c
}

// porthopTool is the Manager surface the commands need.
type porthopTool interface {
	Inspect(ctx context.Context) porthop.Status
	Clear(ctx context.Context) error
}

// newPorthopTool builds the Manager of the configuration in path. It reads the
// same state directory and backend choice as the running agent. Tests replace it.
var newPorthopTool = func(path string) (porthopTool, error) {
	cfg, err := agentd.LoadConfig(path)
	if err != nil {
		return nil, err
	}
	opts := xrayKernelOptions(path, cfg)
	backend := "auto"
	if cfg.Agent != nil {
		backend = cfg.Agent.PortHopBackendName()
	}

	return porthop.New(porthop.Config{
		Enabled:  true, // the commands act whatever the agent's local switch says
		Backend:  backend,
		StateDir: filepath.Clean(opts.StateDir),
	}), nil
}

func porthopStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show the firewall backend and the port-hop rules recorded by the agent",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := findConfig()
			if err != nil {
				return err
			}
			tool, err := newPorthopTool(path)
			if err != nil {
				return err
			}

			return porthopStatus(cmd.Context(), tool, cmd.OutOrStdout())
		},
	}
}

// porthopStatus is separate from the command so it can be tested.
func porthopStatus(ctx context.Context, tool porthopTool, out io.Writer) error {
	st := tool.Inspect(ctx)
	if !st.Available {
		fmt.Fprintf(out, "端口跳跃: 无可用防火墙后端（需要 nft 或 iptables）\n")
		if st.LastError != "" {
			fmt.Fprintf(out, "  原因: %s\n", st.LastError)
		}

		return nil
	}
	fmt.Fprintf(out, "端口跳跃: 后端=%s 规则=%d\n", st.Backend, len(st.Rules))
	if st.Note != "" {
		fmt.Fprintf(out, "  说明: %s\n", st.Note)
	}
	for _, r := range st.Rules {
		state := "生效"
		if !r.OK {
			state = "缺失"
			if r.Reason != "" {
				state += "（" + r.Reason + "）"
			}
		}
		fmt.Fprintf(out, "  节点 %d  %s %s -> %d  %s\n", r.NodeID, r.Proto, r.Ports, r.To, state)
	}
	if st.LastError != "" {
		fmt.Fprintf(out, "  错误: %s\n", st.LastError)
	}

	return nil
}

func porthopClearCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "clear",
		Short: "Remove every port-hop rule and the table or chain the agent created",
		Long: "Delete the nftables tables (w1ncray_porthop) or the iptables chain\n" +
			"(W1NCRAY-PORTHOP) the agent created for Hysteria port hopping, and forget the\n" +
			"recorded state. It touches nothing else. A running agent installs the rules\n" +
			"again at its next poll when the panel still hands them out.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := findConfig()
			if err != nil {
				return err
			}
			tool, err := newPorthopTool(path)
			if err != nil {
				return err
			}

			return porthopClear(cmd.Context(), tool, cmd.OutOrStdout())
		},
	}
}

// porthopClear is separate from the command so it can be tested.
func porthopClear(ctx context.Context, tool porthopTool, out io.Writer) error {
	if err := tool.Clear(ctx); err != nil {
		return fmt.Errorf("清除端口跳跃规则: %w", err)
	}
	fmt.Fprintln(out, "已清除端口跳跃规则")

	return nil
}
