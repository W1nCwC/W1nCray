package panel

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/W1nCwC/W1nCray/agent/filesync"
	"github.com/W1nCwC/W1nCray/core"
)

// CoreValidator pre-checks a staged managed-file set offline with the same xray
// kernel the running instance uses (design section 3.4 step 3). It lives in
// panel because panel is what owns the live instance options: the four JSON
// paths, the DNS name servers of the running nodes, and the config loader for
// config.yml.
type CoreValidator struct {
	// base is the live instance's core options. The validator overrides the
	// four JSON paths with their staged copies.
	base core.Options
	// configPath is the live config.yml, needed to pre-check a staged
	// config.yml with the full LoadConfig.
	configPath string
}

// NewCoreValidator builds the validator for one panel. The options are read
// once, at construction: a validation must see the configuration the running
// instance was built from, not a half-updated one.
//
// The caller must hold p.mu (start() builds it while it owns the lock), so this
// helper must not take it again.
func (p *Panel) NewCoreValidator() *CoreValidator {
	cfg := p.cfg
	var opts core.Options
	if cfg != nil {
		var ns []core.NameServer
		for _, n := range p.nodes {
			ns = append(ns, n.NameServers()...)
		}
		opts = coreOptions(cfg, ns)
	}
	return &CoreValidator{base: opts, configPath: p.path}
}

var _ filesync.Validator = (*CoreValidator)(nil)

// ValidateStaged checks every staged file and returns one error per problem.
// A managed file that is not part of the set keeps its live path, so the
// combination (staged route.json plus the live custom_inbound.json) is what
// gets validated — exactly what the instance would be built from.
func (v *CoreValidator) ValidateStaged(ctx context.Context, dir string, files []filesync.FileRef) []error {
	if err := ctx.Err(); err != nil {
		return []error{err}
	}
	opts := v.base
	staged := map[string]string{}
	for _, f := range files {
		if err := filesync.CheckName(f.Name); err != nil {
			return []error{err}
		}
		p := filepath.Join(dir, f.Name)
		if _, err := os.Stat(p); err != nil {
			return []error{fmt.Errorf("%s: the staged copy is missing: %w", f.Name, err)}
		}
		staged[f.Name] = p
	}
	if p, ok := staged[filesync.NameDNS]; ok {
		opts.DNSConfigPath = p
	}
	if p, ok := staged[filesync.NameRoute]; ok {
		opts.RouteConfigPath = p
	}
	if p, ok := staged[filesync.NameCustomInbound]; ok {
		opts.InboundConfigPath = p
	}
	if p, ok := staged[filesync.NameCustomOutbound]; ok {
		opts.OutboundConfigPath = p
	}

	var errs []error
	errs = append(errs, core.CheckFiles(opts)...)

	// The whole-instance pre-check catches what the per-file check cannot:
	// duplicate tags between custom_inbound.json and the node inbounds, a
	// balancer a rule refers to but nobody declares, and so on. core.New builds
	// the configuration and creates the instance; it never starts it, so no
	// port is bound (only core.Core.Start binds).
	if c, err := core.New(opts); err != nil {
		errs = append(errs, fmt.Errorf("xray instance pre-check: %w", err))
	} else {
		_ = c.Close()
	}

	if p, ok := staged[filesync.NameConfig]; ok {
		if err := v.checkStagedConfig(p); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

// checkStagedConfig pre-checks a staged config.yml with the panel's own loader.
// The copy is written next to the live config.yml, so LoadConfig resolves the
// agent section exactly as the running machine would (including agent.yml
// winning over the staged "Agent:" block); the copy's name never ends in .yml,
// so viper's format detection falls back to the YAML default rather than
// guessing from an extension.
func (v *CoreValidator) checkStagedConfig(staged string) error {
	if v.configPath == "" {
		return errors.New("config.yml: cannot be pre-checked without the live config path")
	}
	raw, err := os.ReadFile(staged)
	if err != nil {
		return fmt.Errorf("config.yml: %w", err)
	}
	if len(raw) == 0 {
		return errors.New("config.yml: the staged copy is empty")
	}
	dir := filepath.Dir(v.configPath)
	tmp, err := os.CreateTemp(dir, ".w1ncray-precheck-*")
	if err != nil {
		return fmt.Errorf("config.yml: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return fmt.Errorf("config.yml: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("config.yml: %w", err)
	}
	if _, err := LoadConfig(tmpName); err != nil {
		return fmt.Errorf("config.yml: %s", strings.TrimSpace(err.Error()))
	}
	return nil
}
