package agentcfg

import (
	"os"
	"path/filepath"
)

// Source tells where the effective agent configuration came from; it is
// reported by "W1nCray check" so an operator can see which file won.
type Source string

const (
	SourceNone     Source = "none"
	SourceAgentYML Source = "agent.yml"
	SourceConfig   Source = "config.yml"
)

// Resolve picks the effective agent section:
//   - agent.yml exists  -> it wins AS A WHOLE (never field-merged with config.yml)
//   - otherwise         -> the config.yml "Agent:" block
//
// It also returns the directory the relative paths must be resolved against:
// the directory of the file that won (rule 5 of the D1 design). A broken
// agent.yml is an error, never a silent fallback: the file's presence is what
// makes it authoritative (design R5).
func Resolve(configPath string, fromConfig *Config) (*Config, Source, string, error) {
	dir := filepath.Dir(configPath)
	agentPath := filepath.Join(dir, FileName)
	cfg, err := Load(agentPath)
	if err != nil {
		return nil, SourceNone, dir, err
	}
	if cfg != nil {
		return cfg, SourceAgentYML, dir, nil
	}
	if fromConfig != nil {
		return fromConfig, SourceConfig, dir, nil
	}
	return nil, SourceNone, dir, nil
}

// WarnIfShadowed reports (for logging) that both sources exist and config.yml's
// Agent block is being ignored. It never returns an error: the precedence is
// well defined, an operator just needs to be told. agentPath is the file that
// won.
func WarnIfShadowed(configPath string, fromConfig *Config) (shadowed bool, agentPath string) {
	if fromConfig == nil {
		return false, ""
	}
	agentPath = filepath.Join(filepath.Dir(configPath), FileName)
	if _, err := os.Stat(agentPath); err != nil {
		return false, ""
	}
	return true, agentPath
}
