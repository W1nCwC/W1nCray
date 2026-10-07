// Package cmd implements the W1nCray agent command line.
package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/W1nCwC/W1nCray/agentd"
)

var configFile string

var rootCmd = &cobra.Command{
	Use:   "W1nCray",
	Short: "W1nCray agent: panel link, forwarding kernels, terminal and files",
	RunE: func(cmd *cobra.Command, args []string) error {
		return run()
	},
	SilenceUsage: true,
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "", "config file (default: ./config.yml, /etc/W1nCray/config.yml)")
	// `run` is explicit as well as the default action, so service units and
	// operators can always name it.
	rootCmd.AddCommand(&cobra.Command{
		Use:          "run",
		Short:        "Run the agent (same as running W1nCray with no subcommand)",
		RunE:         func(cmd *cobra.Command, args []string) error { return run() },
		SilenceUsage: true,
	})
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func findConfig() (string, error) {
	if configFile != "" {
		return filepath.Abs(configFile)
	}
	candidates := []string{"config.yml", "config.yaml", "/etc/W1nCray/config.yml"}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "config.yml"))
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return filepath.Abs(c)
		}
	}
	return "", fmt.Errorf("no config file found; use -c to set one")
}

func run() error {
	showVersion()
	path, err := findConfig()
	if err != nil {
		return err
	}
	lock, err := acquireInstanceLock(path)
	if err != nil {
		return err
	}
	defer lock.release()
	cfg, err := agentd.LoadConfig(path)
	if err != nil {
		return err
	}

	// A committed self_update asks the process to exit so the self-update
	// watchdog (or the service manager) brings the binary that was put in place
	// back up. The signal is the existing, graceful shutdown path.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	agentd.RequestRestart = func() {
		select {
		case sig <- syscall.SIGTERM:
		default:
		}
	}

	// With a panel link the bootstrap layer owns the start-up watchdog: it has
	// the event channel and the "the panel answered" hook. Without one there is
	// nothing to reach, so the update is confirmed here.
	startup := agentd.SelfUpdateStartup(cfg)

	// The Xray kernel runs in its own process (W1nCray-xray). X1 leaves the
	// service handle nil: the agent degrades to "Xray 内核未安装" for managed
	// Xray files. X2 installs the kernel and provides the handle here.
	d := agentd.New(path, cfg, agentd.Options{})
	if err := d.Start(); err != nil {
		return err
	}
	if startup != nil {
		if err := startup.Confirm(); err != nil {
			log.Warnf("agent: confirming the self-update: %v", err)
		}
		// No panel link: the pending self-update is confirmed now, so the
		// start-up migration (PLAN v11 §2.6) may bring the Xray kernel service
		// up. With a panel link, bootstrap runs it once the panel answered.
		d.EnsureXray(context.Background())
	}

	<-sig
	log.Info("shutting down")
	d.Close()
	return nil
}
