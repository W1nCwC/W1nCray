// Command W1nCray-xray is the W1nCray Xray kernel: the Xray-core instance, the
// Xboard node controllers (static Nodes and panel machine mode), the
// rate/device dispatcher and the configuration-file watcher, in a process of
// its own.
//
// It is what the agent installs as the "xray" kernel; the agent itself does not
// link Xray-core.
package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	xcore "github.com/xtls/xray-core/core"

	"github.com/W1nCwC/W1nCray/agent/filesync"
	"github.com/W1nCwC/W1nCray/agent/xrayapi"
	"github.com/W1nCwC/W1nCray/lockfile"
	"github.com/W1nCwC/W1nCray/xraynode"
)

var configFile string

var rootCmd = &cobra.Command{
	Use:   "W1nCray-xray",
	Short: "W1nCray Xray kernel (Xray-core + Xboard node controllers)",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runKernel()
	},
	SilenceUsage: true,
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "", "config file (default: ./config.yml, /etc/W1nCray/config.yml)")
	rootCmd.AddCommand(runCmd())
	rootCmd.AddCommand(versionCmd())
	rootCmd.AddCommand(checkCmd())
	rootCmd.AddCommand(checkStagedCmd())
	rootCmd.AddCommand(x25519Cmd())
}

// runCmd is explicit as well as the default action, so the systemd unit and
// operators can always name it.
func runCmd() *cobra.Command {
	return &cobra.Command{
		Use:          "run",
		Short:        "Run the Xray kernel (same as running W1nCray-xray with no subcommand)",
		RunE:         func(cmd *cobra.Command, args []string) error { return runKernel() },
		SilenceUsage: true,
	}
}

func main() {
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

// runKernel is the default action: serve the Xray instance.
func runKernel() error {
	path, err := findConfig()
	if err != nil {
		return err
	}
	setAssetLocation(path)
	// The kernel lock is separate from the agent's (<config>.lock): the two
	// programs run side by side against the same configuration.
	lock, err := lockfile.Acquire(path+".xray.lock", "W1nCray-xray", path)
	if err != nil {
		return err
	}
	defer lock.Release()
	cfg, err := xraynode.LoadConfig(path)
	if err != nil {
		return err
	}
	fmt.Printf("W1nCray-xray v%s (Xray-core %s)\n", xraynode.Version, xcore.Version())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		cancel()
	}()
	return xraynode.Run(ctx, path, cfg)
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version (kernel and Xray-core)",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("W1nCray-xray v%s (Xray-core %s)\n", xraynode.Version, xcore.Version())
		},
	}
}

var checkOnline bool

func checkCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "check",
		Short: "Validate the Xray config (and with --online, the panel nodes) without serving traffic",
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := findConfig()
			if err != nil {
				return err
			}
			setAssetLocation(path)
			return xraynode.Check(path, checkOnline, os.Stdout)
		},
	}
	c.Flags().BoolVar(&checkOnline, "online", false, "also fetch every node from the panel and build its inbound")
	return c
}

var (
	stagedDir   string
	stagedFiles string
)

// stagedResult is the JSON document check-staged prints.
type stagedResult struct {
	OK     bool                  `json:"ok"`
	Errors []xrayapi.StagedError `json:"errors"`
}

func checkStagedCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "check-staged",
		Short: "Pre-check a staged managed-file set and print the result as JSON",
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := findConfig()
			if err != nil {
				return err
			}
			setAssetLocation(path)
			names := splitNames(stagedFiles)
			if stagedDir == "" || len(names) == 0 {
				return fmt.Errorf("--dir and --files are required")
			}
			errs := xraynode.CheckStaged(context.Background(), path, stagedDir, names)
			res := stagedResult{OK: len(errs) == 0, Errors: stagedErrors(errs)}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(res); err != nil {
				return err
			}
			if !res.OK {
				os.Exit(1)
			}
			return nil
		},
	}
	c.Flags().StringVar(&stagedDir, "dir", "", "staging directory holding the staged files")
	c.Flags().StringVar(&stagedFiles, "files", "", "comma-separated managed-file names to check")
	return c
}

// splitNames parses the --files list.
func splitNames(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// stagedErrors maps the validator's errors onto the JSON error list. An error
// that starts with a managed-file name is attributed to that file; the others
// keep an empty file field.
func stagedErrors(errs []error) []xrayapi.StagedError {
	out := make([]xrayapi.StagedError, 0, len(errs))
	for _, e := range errs {
		msg := e.Error()
		file := ""
		for _, n := range filesync.ManagedNames {
			if strings.HasPrefix(msg, n+": ") {
				file = n
				msg = strings.TrimPrefix(msg, n+": ")
				break
			}
		}
		out = append(out, xrayapi.StagedError{File: file, Message: msg})
	}
	return out
}

var x25519Input string

func x25519Cmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "x25519",
		Short: "Generate a REALITY key pair (same format as `xray x25519`)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return x25519()
		},
	}
	c.Flags().StringVarP(&x25519Input, "input", "i", "", "derive from this base64 private key")
	return c
}

func x25519() error {
	var priv *ecdh.PrivateKey
	var err error
	if x25519Input != "" {
		b, derr := base64.RawURLEncoding.DecodeString(x25519Input)
		if derr != nil {
			return fmt.Errorf("decode private key: %w", derr)
		}
		priv, err = ecdh.X25519().NewPrivateKey(b)
	} else {
		priv, err = ecdh.X25519().GenerateKey(rand.Reader)
	}
	if err != nil {
		return err
	}
	fmt.Printf("Private key: %s\n", base64.RawURLEncoding.EncodeToString(priv.Bytes()))
	fmt.Printf("Public key: %s\n", base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()))
	return nil
}
