package cmd

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var (
	defaultFiles fs.FS
	initDir      string
	initForce    bool
)

// SetDefaultFiles provides the example config files embedded in the binary.
func SetDefaultFiles(f fs.FS) { defaultFiles = f }

func init() {
	c := &cobra.Command{
		Use:   "init",
		Short: "Write the default config files into a directory",
		RunE: func(cmd *cobra.Command, args []string) error {
			return writeDefaults(initDir, initForce)
		},
	}
	c.Flags().StringVar(&initDir, "dir", "/etc/W1nCray", "target directory")
	c.Flags().BoolVar(&initForce, "force", false, "overwrite existing files")
	rootCmd.AddCommand(c)
}

func writeDefaults(dir string, force bool) error {
	if defaultFiles == nil {
		return fmt.Errorf("no default files embedded in this build")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return fs.WalkDir(defaultFiles, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		name := p
		perm := os.FileMode(0o644)
		if p == "config.yml.example" {
			name, perm = "config.yml", 0o600
		}
		dst := filepath.Join(dir, name)
		if _, err := os.Stat(dst); err == nil && !force {
			fmt.Printf("保留已存在的 %s\n", dst)
			return nil
		}
		b, err := fs.ReadFile(defaultFiles, p)
		if err != nil {
			return err
		}
		if err := os.WriteFile(dst, b, perm); err != nil {
			return err
		}
		fmt.Printf("写入 %s\n", dst)
		return nil
	})
}
