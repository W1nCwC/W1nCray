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
	p := panel.New(path, cfg)
	if err := p.Start(); err != nil {
		return err
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	log.Info("shutting down")
	p.Close()
	return nil
}
