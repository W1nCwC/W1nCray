// Package cmd implements the W1nCray command line.
package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/W1nCwC/W1nCray/agent/selfupdate"
	"github.com/W1nCwC/W1nCray/panel"
)

var configFile string

var rootCmd = &cobra.Command{
	Use:   "W1nCray",
	Short: "Xboard node backend built on the official Xray-core",
	RunE: func(cmd *cobra.Command, args []string) error {
		return run()
	},
	SilenceUsage: true,
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "", "config file (default: ./config.yml, /etc/W1nCray/config.yml)")
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

// setAssetLocation lets Xray find geoip.dat/geosite.dat next to the config
// unless the location is set explicitly.
func setAssetLocation(configPath string) {
	if os.Getenv("XRAY_LOCATION_ASSET") == "" && os.Getenv("xray.location.asset") == "" {
		os.Setenv("XRAY_LOCATION_ASSET", filepath.Dir(configPath))
	}
}

func run() error {
	showVersion()
	path, err := findConfig()
	if err != nil {
		return err
	}
	setAssetLocation(path)
	lock, err := acquireInstanceLock(path)
	if err != nil {
		return err
	}
	defer lock.release()
	cfg, err := panel.LoadConfig(path)
	if err != nil {
		return err
	}

	// A committed self_update asks the process to exit so the self-update
	// watchdog (or the service manager) brings the binary that was put in place
	// back up. The signal is the existing, graceful shutdown path: kernels are
	// stopped and Xray is closed before this process returns.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	panel.RequestRestart = func() {
		select {
		case sig <- syscall.SIGTERM:
		default:
		}
	}

	// With a panel link the bootstrap layer owns the start-up watchdog: it has
	// the event channel and the "the panel answered" hook. Without one there is
	// nothing to reach, so the update is confirmed here.
	startup := selfUpdateStartup(cfg)

	p := panel.New(path, cfg)
	if err := p.Start(); err != nil {
		return err
	}
	if startup != nil {
		if err := startup.Confirm(); err != nil {
			log.Warnf("agent: confirming the self-update: %v", err)
		}
	}

	<-sig
	log.Info("shutting down")
	p.Close()
	return nil
}

// selfUpdateStartup prepares the start-up side of a committed self_update for
// an agent with no panel link. It returns nil when there is nothing to do
// (agent disabled, no state directory, or a panel is configured: bootstrap
// then owns the watchdog).
func selfUpdateStartup(cfg *panel.Config) *selfupdate.Startup {
	a := cfg.Agent
	if a == nil || !a.Enabled || a.StateDir == "" {
		return nil
	}
	if a.Panel != nil && a.Panel.Enabled {
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return nil
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	up, err := selfupdate.New(selfupdate.Options{
		ExePath:  exe,
		StateDir: a.StateDir,
		Log:      log.StandardLogger(),
	})
	if err != nil {
		log.Warnf("agent: self-update start-up check skipped: %v", err)
		return nil
	}
	st := up.BeginStartup()
	if rb, ok := st.TakeRollback(); ok {
		log.Warnf("agent: self_update.rolled_back: version %s: %s", rb.Version, rb.Reason)
	}
	// A local-only agent has no panel to wait for; a watchdog would report
	// self_update.stalled against a link that was never configured.
	return st
}
