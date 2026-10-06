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
	// Local lists builds that are already on this machine instead of in a
	// GitHub release (release/build.sh writes dist/W1nCray-linux-<arch>.gz).
	// Their hashes are computed from the file on disk; there is no upstream
	// claim to cross-check, which is why they exist only for artifacts built
	// and hashed on the machine running manifestgen.
	Local []LocalAssetCfg `yaml:"local"`
}

// LocalAssetCfg is one build produced by the release scripts in this
// repository, described by its path on disk.
type LocalAssetCfg struct {
	// File is the archive path (dist/W1nCray-linux-amd64.gz).
	File string `yaml:"file"`
	// Target is the manifest platform key, e.g. linux/amd64.
	Target string `yaml:"target"`
	// To is the installed file name; empty means run.binary.
	To string `yaml:"to"`
	// From is the member name. A raw gz stream has none, so it defaults to
	// the archive's base name; tar.gz/zip builds must set it explicitly.
	From string `yaml:"from"`
	// Mode is the installed file mode; empty means 0755.
	Mode string `yaml:"mode"`
	// Archive overrides the format inferred from File's extension.
	Archive string `yaml:"archive"`
	// Variant is the manifest variant token (softfloat, musl-full, ...).
	Variant string `yaml:"variant"`
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
		if k.Name == "" || k.Version == "" {
			return fmt.Errorf("kernel #%d: name and version are required", i+1)
		}
		local := len(k.Local) > 0
		if k.Repo == "" && !local {
			return fmt.Errorf("%s: repo is required for GitHub-backed kernels", k.Name)
		}
		if k.Tag == "" && k.Repo != "" {
			k.Tag = "v" + k.Version
		}
		if k.License.SourceURL == "" && k.Repo != "" {
			k.License.SourceURL = "https://github.com/" + k.Repo
		}
		if k.Channel == "" {
			k.Channel = "stable"
		}
		if k.MinAgent == "" {
			k.MinAgent = c.MinAgent
		}
		if len(k.Targets) == 0 && !local {
			return fmt.Errorf("%s: no targets", k.Name)
		}
		for key, t := range k.Targets {
			if t != nil && t.Asset == "" {
				k.Targets[key] = nil // "linux/riscv64:" with no body means unavailable
			}
		}
		for j := range k.Local {
			la := &k.Local[j]
			if la.File == "" || la.Target == "" {
				return fmt.Errorf("%s: local #%d needs file and target", k.Name, j+1)
			}
			if _, dup := k.Targets[la.Target]; dup {
				return fmt.Errorf("%s: target %s is declared both in targets and local", k.Name, la.Target)
			}
		}
	}
	return nil
}
