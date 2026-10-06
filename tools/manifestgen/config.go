package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Config is the small build description (YAML or JSON) that tells manifestgen
// which upstream release assets make up each kernel/target. It contains no
// hashes: those are computed from the downloads and cross-checked.
type Config struct {
	// Sequence is the manifest sequence number; it must exceed that of the
	// previously published manifest. Overridable with -sequence.
	Sequence int64 `yaml:"sequence"`
	// ValidDays is the lifetime from issued_at (default 90).
	ValidDays int `yaml:"valid_days"`
	// MinAgent is the default min_agent of kernels that do not set their own.
	MinAgent string `yaml:"min_agent"`
	// Mirrors are ordered URL templates tried before the upstream URL:
	// {name} {version} {asset} are substituted. Example:
	//   https://mirror.example.com/kernels/{name}/{version}/{asset}
	Mirrors []string `yaml:"mirrors"`
	// NoUpstream leaves the upstream GitHub URL out of the url lists.
	NoUpstream bool `yaml:"no_upstream"`

	Kernels []KernelCfg `yaml:"kernels"`
}

// KernelCfg describes one kernel version.
type KernelCfg struct {
	Name         string         `yaml:"name"`
	Version      string         `yaml:"version"` // without leading v
	Repo         string         `yaml:"repo"`    // owner/name
	Tag          string         `yaml:"tag"`     // default "v"+version
	Channel      string         `yaml:"channel"`
	MinAgent     string         `yaml:"min_agent"`
	License      LicenseCfg     `yaml:"license"`
	Capabilities map[string]any `yaml:"capabilities"`
	Run          RunCfg         `yaml:"run"`
	Revoked      []RevokedCfg   `yaml:"revoked"`

	// Checksums names an upstream checksum file (sha256sum format) that is
	// cross-checked with GitHub's asset digest. Dgst enables the per-asset
	// "<asset>.dgst" files (Xray format, "SHA2-256= <hex>").
	Checksums *ChecksumsCfg `yaml:"checksums"`

	// Extract is the default list of files to take from each archive.
	Extract []ExtractCfg `yaml:"extract"`
	// Targets maps manifest target keys to upstream assets; null (or an
	// empty value) marks the kernel unavailable on that platform.
	Targets map[string]*TargetCfg `yaml:"targets"`
}

// LicenseCfg, RunCfg and RevokedCfg mirror the manifest types with YAML keys.
type LicenseCfg struct {
	SPDX      string `yaml:"spdx"`
	File      string `yaml:"file"`
	SourceURL string `yaml:"source_url"`
}

type RunCfg struct {
	Binary       string   `yaml:"binary"`
	VersionCmd   []string `yaml:"version_cmd"`
	VersionRegex string   `yaml:"version_regex"`
}

type RevokedCfg struct {
	Version string `yaml:"version"`
	SHA256  string `yaml:"sha256"`
	Reason  string `yaml:"reason"`
}

// ChecksumsCfg selects the upstream checksum source.
type ChecksumsCfg struct {
	Asset string `yaml:"asset"` // e.g. checksums.txt
	Dgst  bool   `yaml:"dgst"`  // per-asset .dgst files
}

// TargetCfg maps one platform to one upstream asset.
type TargetCfg struct {
	Asset   string       `yaml:"asset"`
	Variant string       `yaml:"variant"`
	Archive string       `yaml:"archive"` // default from the file extension
	Extract []ExtractCfg `yaml:"extract"` // overrides the kernel default
}

// ExtractCfg is one wanted member. From may use {asset_base} (the asset
// name without .tar.gz/.zip) and {version}.
type ExtractCfg struct {
	From string `yaml:"from"`
	To   string `yaml:"to"`
	Mode string `yaml:"mode"` // default 0755
}

func loadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var c Config
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := c.check(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

func (c *Config) check() error {
	if len(c.Kernels) == 0 {
		return fmt.Errorf("no kernels")
	}
	for i := range c.Kernels {
		k := &c.Kernels[i]
		k.Version = strings.TrimPrefix(k.Version, "v")
		if k.Name == "" || k.Version == "" || k.Repo == "" {
			return fmt.Errorf("kernel #%d: name, version and repo are required", i+1)
		}
		if k.Tag == "" {
			k.Tag = "v" + k.Version
		}
		if k.License.SourceURL == "" {
			k.License.SourceURL = "https://github.com/" + k.Repo
		}
		if k.Channel == "" {
			k.Channel = "stable"
		}
		if k.MinAgent == "" {
			k.MinAgent = c.MinAgent
		}
		if len(k.Targets) == 0 {
			return fmt.Errorf("%s: no targets", k.Name)
		}
		for key, t := range k.Targets {
			if t != nil && t.Asset == "" {
				k.Targets[key] = nil // "linux/riscv64:" with no body means unavailable
			}
		}
	}
	return nil
}
