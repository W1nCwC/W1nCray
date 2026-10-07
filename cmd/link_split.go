package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/W1nCwC/W1nCray/agent/agentcfg"
)

// runSplit is `W1nCray link --split`: the layout-only migration for a machine
// that is already in panel machine mode (its nodes were converted earlier, so
// there is nothing left for the node conversion to do). The existing Agent:
// block of config.yml moves, verbatim, to <config dir>/agent.yml; config.yml
// keeps a one-line comment in its place. Nothing else changes: no token, no
// panel URL, no node. --noterminal adds Terminal: {Enabled: false}.
//
// Safety: the new agent.yml must decode to exactly the Agent block it replaces
// (apart from the optional Terminal opt-out) and must load and validate on its
// own; after the write, the full offline check of the new layout must not
// report a problem the old layout did not have, otherwise both files are
// restored. Both originals are backed up first.
func runSplit(configPath string, opts linkOptions, out io.Writer) error {
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("读取配置 %s 失败: %w", configPath, err)
	}
	dir := filepath.Dir(configPath)
	agentPath := filepath.Join(dir, "agent.yml")
	_, statErr := os.Stat(agentPath)
	agentExists := statErr == nil
	if agentExists && !opts.Force {
		return fmt.Errorf("%s 已存在：配置已经是分离布局；如需重做请加 --force（会先备份）", agentPath)
	}

	text := string(raw)
	newline := "\n"
	if strings.Contains(text, "\r\n") {
		newline = "\r\n"
	}
	src := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	lines := make([]linkLine, len(src))
	for i, s := range src {
		lines[i] = makeLine(s)
	}
	keyIdx, ok := topLevelKey(lines, "Agent")
	if !ok {
		return errors.New("config.yml 里没有 Agent: 块，没有可拆分的内容（新机器请用 link --panel ... 转换节点）")
	}
	if v := strings.TrimSpace(stripInlineComment(strings.SplitN(src[keyIdx], ":", 2)[1])); v != "" {
		return errors.New("Agent: 不是块写法（同一行带了值），无法逐行拆分；请手工改写")
	}
	end := blockEnd(lines, keyIdx, len(lines), 0)

	// The block body, dedented by the indentation of its first key.
	body := src[keyIdx+1 : end]
	indent := -1
	for i := keyIdx + 1; i < end; i++ {
		if !lines[i].blank && !lines[i].comment {
			indent = lines[i].indent
			break
		}
	}
	if indent <= 0 {
		return errors.New("Agent: 块是空的，没有可拆分的内容")
	}
	var agentLines []string
	for _, s := range body {
		if strings.TrimSpace(s) == "" {
			agentLines = append(agentLines, "")
			continue
		}
		lead := len(s) - len(strings.TrimLeft(s, " "))
		if lead < indent {
			// A comment shallower than the block's keys: keep it at column 0.
			agentLines = append(agentLines, strings.TrimLeft(s, " "))
			continue
		}
		agentLines = append(agentLines, s[indent:])
	}
	for len(agentLines) > 0 && agentLines[len(agentLines)-1] == "" {
		agentLines = agentLines[:len(agentLines)-1]
	}

	// Equivalence: the moved text must decode to the same value as the block.
	var whole map[string]any
	if err := yaml.Unmarshal([]byte(strings.ReplaceAll(text, "\r\n", "\n")), &whole); err != nil {
		return fmt.Errorf("config.yml 不是合法 YAML: %w", err)
	}
	var moved map[string]any
	if err := yaml.Unmarshal([]byte(strings.Join(agentLines, "\n")), &moved); err != nil {
		return fmt.Errorf("拆出的 agent.yml 不是合法 YAML（未改动任何文件）: %w", err)
	}
	if !reflect.DeepEqual(whole["Agent"], any(moved)) {
		return errors.New("拆出的 agent.yml 与原 Agent: 块解析结果不一致（未改动任何文件）")
	}
	if opts.NoTerminal {
		if _, has := moved["Terminal"]; has {
			return errors.New("Agent: 块里已有 Terminal 设置；--noterminal 不会覆盖它，请手工改为 Enabled: false")
		}
		agentLines = append(agentLines, "", "# Interactive terminal disabled locally (W1nCray link --split --noterminal).", "Terminal: {Enabled: false}")
	}
	ts := time.Now().Format("20060102-150405")
	header := []string{
		"# W1nCray agent configuration (moved from the Agent: block of config.yml by",
		"# `W1nCray link --split` on " + ts + "). config.yml describes only the xray kernel;",
		"# this file is the agent's own configuration and the panel never writes it.",
	}
	agentText := strings.Join(append(header, agentLines...), "\n") + "\n"

	// config.yml without the block.
	marker := "# Agent: moved to agent.yml by `W1nCray link --split` on " + ts + " (original backed up next to this file)"
	newConfig := append(append(append([]string{}, src[:keyIdx]...), marker), src[end:]...)
	configText := strings.Join(newConfig, newline)
	if newline == "\r\n" {
		configText = strings.ReplaceAll(strings.Join(newConfig, "\n"), "\n", "\r\n")
	}

	fmt.Fprintf(out, "布局拆分（--split）：\n  配置文件: %s\n  Agent: 块 %d 行 → %s\n", configPath, end-keyIdx, agentPath)
	if opts.NoTerminal {
		fmt.Fprintln(out, "  终端: 本机关闭（Terminal: {Enabled: false}）")
	} else {
		fmt.Fprintln(out, "  终端: 默认开启（未写 Terminal 设置）")
	}
	if opts.DryRun {
		fmt.Fprintln(out, "（dry-run：未写入任何文件）")
		return nil
	}

	// The staged agent.yml must load and validate on its own (relative paths
	// resolve against its own directory, which is the config directory).
	stage, err := os.CreateTemp(dir, ".agent-split-*.yml")
	if err != nil {
		return fmt.Errorf("创建校验临时文件失败: %w", err)
	}
	stagePath := stage.Name()
	defer os.Remove(stagePath)
	if _, err := stage.WriteString(agentText); err != nil {
		stage.Close()
		return fmt.Errorf("写入校验临时文件失败: %w", err)
	}
	stage.Chmod(0o600)
	stage.Close()
	cfg, err := agentcfg.Load(stagePath)
	if err != nil {
		return fmt.Errorf("拆出的 agent.yml 无法加载（未改动任何文件）: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("拆出的 agent.yml 未通过校验（未改动任何文件）: %w", err)
	}

	baseline := map[string]bool{}
	if !opts.SkipCheck {
		for _, f := range checkConfigFailures(configPath) {
			baseline[linkFailureKey(f, configPath)] = true
		}
	}

	backupPath, err := backupConfig(configPath, raw, ts)
	if err != nil {
		return err
	}
	agentBackup, err := agentcfg.WriteFile(agentPath, []byte(agentText))
	if err != nil {
		return fmt.Errorf("写入 %s 失败（%s 未改动）: %w", agentPath, configPath, err)
	}
	if err := writeFileAtomic(configPath, []byte(configText)); err != nil {
		restoreAgentYML(agentPath, agentBackup, agentExists)
		return fmt.Errorf("替换 %s 失败（已恢复 agent.yml；原配置备份 %s）: %w", configPath, backupPath, err)
	}

	if !opts.SkipCheck {
		var added []string
		for _, f := range dedupeFailures(checkConfigFailures(configPath)) {
			if !baseline[linkFailureKey(f, configPath)] {
				added = append(added, f)
			}
		}
		if len(added) > 0 {
			os.WriteFile(configPath, raw, 0o600)
			restoreAgentYML(agentPath, agentBackup, agentExists)
			fmt.Fprintln(out, "拆分后的配置出现了原配置没有的问题，已自动恢复原文件：")
			for _, f := range added {
				fmt.Fprintln(out, "  "+strings.TrimSpace(f))
			}
			return errors.New("拆分未通过校验，已恢复原状")
		}
	}

	fmt.Fprintf(out, "已写入 %s（0600）\n", agentPath)
	if agentBackup != "" {
		fmt.Fprintf(out, "原 agent.yml 备份 %s\n", agentBackup)
	}
	fmt.Fprintf(out, "已更新 %s（原文件备份 %s）\n", configPath, backupPath)
	fmt.Fprintln(out, "下一步：W1nCray check 确认无误后执行 W1nCray restart（link 从不重启服务）。")
	fmt.Fprintf(out, "回滚：cp %s %s && rm %s && W1nCray restart\n", backupPath, configPath, agentPath)
	return nil
}

// writeFileAtomic replaces path with data through a temporary file in the same
// directory, keeping mode 0600.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	return os.Rename(name, path)
}
