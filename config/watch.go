// This file holds the two facts about the Xray configuration that the kernel
// and the agent must agree on: which files the kernel watches, and how the
// content fingerprint of that file set is computed.
//
// The kernel (package xraynode) watches the files and publishes the fingerprint
// through its status endpoint; the agent recomputes the same fingerprint after
// a managed-file apply and waits for the kernel to report it (PLAN v11 §C). One
// implementation, linked by both programs, is what keeps the two from drifting
// apart.
package config

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
)

// WatchedFiles lists the files whose content the Xray kernel watches for
// reloads: config.yml itself, the four JSON configuration files it names and
// every node's RuleListPath. A nil config still yields the config file.
func (c *Config) WatchedFiles(configPath string) []string {
	files := make([]string, 0, 6)
	if configPath != "" {
		files = append(files, configPath)
	}
	if c == nil {
		return files
	}
	for _, f := range []string{c.DnsConfigPath, c.RouteConfigPath, c.InboundConfigPath, c.OutboundConfigPath} {
		if f != "" {
			files = append(files, f)
		}
	}
	for _, n := range c.NodesConfig {
		if n != nil && n.ApiConfig != nil && n.ApiConfig.RuleListPath != "" {
			files = append(files, n.ApiConfig.RuleListPath)
		}
	}
	return files
}

// Fingerprint hashes the names and contents of files. A missing or unreadable
// file counts as its own state ("absent"), so a file that disappears changes
// the fingerprint exactly like a content change does.
func Fingerprint(files []string) string {
	h := sha256.New()
	for _, f := range files {
		h.Write([]byte(f))
		h.Write([]byte{0})
		if b, err := os.ReadFile(f); err == nil {
			sum := sha256.Sum256(b)
			h.Write(sum[:])
		} else {
			h.Write([]byte("absent"))
		}
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}
