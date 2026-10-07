package cmd

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/W1nCwC/W1nCray/agent/agentcfg"
	"github.com/W1nCwC/W1nCray/agent/panelclient"
	"github.com/W1nCwC/W1nCray/common/cert"
	"github.com/W1nCwC/W1nCray/node"
	"github.com/W1nCwC/W1nCray/panel"
)

// linkOptions configures `W1nCray link`.
type linkOptions struct {
	Panel              string
	Machine            int
	Token              string
	TokenFile          string
	PortRange          string
	AllowHTTP          bool
	DryRun             bool
	IgnoreAPIOverrides bool
	SkipCheck          bool
	// NoTerminal writes Terminal: {Enabled: false} to agent.yml. The terminal
	// is ON by default (ruling 17), so only the opt-out is ever written.
	NoTerminal bool
	// Force allows link to replace an existing agent.yml. The old file is
	// backed up first.
	Force bool
	// Split is the layout-only migration (runSplit): move the existing Agent:
	// block to agent.yml without converting any node.
	Split bool
}

func init() {
	var opts linkOptions
	c := &cobra.Command{
		Use:   "link",
		Short: "Turn the static Nodes of config.yml into panel machine mode (agent.yml)",
		Long: "Rewrite config.yml in place so the nodes of one panel run in machine mode:\n" +
			"every matching Nodes entry is commented out (for rollback) and its\n" +
			"ControllerConfig is copied, verbatim, under Panel.NodeControllers[<node id>]\n" +
			"in <config dir>/agent.yml.\n" +
			"The agent configuration no longer lives in config.yml: an existing Agent:\n" +
			"block is migrated to agent.yml and replaced by a one-line comment. An\n" +
			"agent.yml that is already there is never overwritten unless --force is\n" +
			"given, and then only after a backup. agent.yml is written atomically.\n" +
			"The files are edited line by line, so comments and unrelated keys survive.\n" +
			"The machine token is written to <config dir>/agent.token (0600) and never\n" +
			"appears in config.yml, agent.yml, on stdout or in an error.\n" +
			"The interactive terminal is ON by default; --noterminal writes\n" +
			"Terminal: {Enabled: false} to agent.yml.",
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := findConfig()
			if err != nil {
				return err
			}
			setAssetLocation(path)
			if opts.Split {
				return runSplit(path, opts, os.Stdout)
			}
			return runLink(path, opts, os.Stdout)
		},
	}
	c.Flags().StringVar(&opts.Panel, "panel", "", "panel URL (https://...; http:// only for loopback or with --allow-http)")
	c.Flags().IntVar(&opts.Machine, "machine", 0, "machine id on the panel (positive)")
	c.Flags().StringVar(&opts.Token, "token", "", "machine token")
	c.Flags().StringVar(&opts.TokenFile, "token-file", "", "read the machine token from this file")
	c.Flags().StringVar(&opts.PortRange, "port-range", "20000-40000", "Agent.Policy.PortRange as LO-HI")
	c.Flags().BoolVar(&opts.AllowHTTP, "allow-http", false, "allow a non-loopback plain http:// panel URL")
	c.Flags().BoolVar(&opts.DryRun, "dry-run", false, "only print what would be done (writes nothing, not even the token)")
	c.Flags().BoolVar(&opts.IgnoreAPIOverrides, "ignore-api-overrides", false, "convert nodes whose ApiConfig has local overrides (SpeedLimit/DeviceLimit/RuleListPath)")
	c.Flags().BoolVar(&opts.SkipCheck, "skip-check", false, "write the converted config without validating it first")
	c.Flags().BoolVar(&opts.NoTerminal, "noterminal", false, "write Terminal: {Enabled: false} to agent.yml (the terminal is ON by default)")
	c.Flags().BoolVar(&opts.Force, "force", false, "replace an existing agent.yml (a backup is written first)")
	c.Flags().BoolVar(&opts.Split, "split", false, "layout only: move the existing Agent: block of config.yml to agent.yml (machines already in machine mode); ignores --panel/--machine/--token")
	rootCmd.AddCommand(c)
}

// linkValidation is the outcome of comparing the full validation of the
// original config with the one of the converted config.
type linkValidation struct {
	// baseline holds the failures the original config already had (set B).
	baseline []string
	// added holds the failures the conversion introduced, i.e. N \ B. A
	// non-empty slice means the conversion must not be written.
	added []string
}

// checkConfigFailures runs the full offline validation of one config and
// returns its failure items. The items are the ones `W1nCray check` prints
// with a "✗", plus the machine-mode controller problems that only matter once
// the node runs and that the offline check therefore does not look at.
func checkConfigFailures(path string) []string {
	failures, _ := panel.CheckReport(path, false, io.Discard)
	if cfg, err := panel.LoadConfig(path); err == nil {
		failures = append(failures, linkMachineNodeFailures(cfg)...)
	}
	return failures
}

// linkMachineNodeFailures reports the machine-mode controller settings the
// offline `W1nCray check` does not validate: a ControllerConfig only takes
// effect once the machine node runs, so `check` (which never builds a machine
// node offline) accepts it. `link` checks the certificate mode of every
// generated NodeControllers entry so a value machine mode cannot use is
// reported as a problem the conversion introduced instead of being written
// silently. It never prints credentials.
func linkMachineNodeFailures(cfg *panel.Config) []string {
	if cfg.Agent == nil || cfg.Agent.Panel == nil {
		return nil
	}
	return linkPanelCertModeFailures(cfg.Agent.Panel)
}

// linkPanelCertModeFailures is linkMachineNodeFailures for an agent panel
// section that was loaded on its own (the generated agent.yml).
func linkPanelCertModeFailures(pc *agentcfg.PanelConfig) []string {
	if pc == nil {
		return nil
	}
	ids := make([]int, 0, len(pc.NodeControllers))
	for id := range pc.NodeControllers {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	var out []string
	for _, id := range ids {
		if f := linkCertModeFailure(fmt.Sprintf("Agent.Panel.NodeControllers[%d]", id), pc.NodeControllers[id]); f != "" {
			out = append(out, f)
		}
	}
	if f := linkCertModeFailure("Agent.Panel.NodeController", pc.NodeController); f != "" {
		out = append(out, f)
	}
	return out
}

// linkCertModeFailure reports an unusable CertConfig.CertMode ("" when the
// mode is one of the supported values or the config has no certificate).
func linkCertModeFailure(where string, cc *node.Config) string {
	if cc == nil || cc.CertConfig == nil {
		return ""
	}
	switch strings.ToLower(strings.TrimSpace(cc.CertConfig.CertMode)) {
	case "", cert.ModeNone, cert.ModeFile, cert.ModeContent, cert.ModeSelf, cert.ModeHTTP, cert.ModeTLS, cert.ModeDNS:
		return ""
	}
	return fmt.Sprintf("✗ %s.CertConfig.CertMode: 不支持的证书模式 %q（可选 none/file/content/self/http/tls/dns）", where, cc.CertConfig.CertMode)
}

// validateLinkOutput validates the original config and the converted one and
// reports which failures the conversion added. The original config is copied
// next to the converted file so relative paths, the token file and the
// referenced JSON files resolve exactly as they do for the conversion.
//
// The comparison key of an item strips the volatile parts of a single run (the
// two temporary file names, any timestamp), so a problem the original config
// already had compares equal and does not block the conversion.
func validateLinkOutput(configPath string, raw []byte, newPath string) (linkValidation, error) {
	basePath, cleanup, err := writeBaselineCopy(configPath, raw)
	if err != nil {
		return linkValidation{}, err
	}
	defer cleanup()

	volatile := []string{basePath, newPath}
	baseFailures := dedupeFailures(checkConfigFailures(basePath))
	newFailures := checkConfigFailures(newPath)

	inBaseline := make(map[string]bool, len(baseFailures))
	for _, f := range baseFailures {
		inBaseline[linkFailureKey(f, volatile...)] = true
	}
	var added []string
	seen := make(map[string]bool)
	for _, f := range newFailures {
		key := linkFailureKey(f, volatile...)
		if inBaseline[key] || seen[key] {
			continue
		}
		seen[key] = true
		added = append(added, f)
	}
	return linkValidation{baseline: baseFailures, added: added}, nil
}

// validateLinkWrite is the pre-write validation of a conversion. It compares
// the full validation of the original config with the one of the converted
// file: only a problem the conversion introduced stops it (with zero changes);
// a problem the original already had is reported as a warning and the
// conversion continues. --skip-check skips the comparison entirely.
func validateLinkWrite(configPath string, raw []byte, newPath string, skipCheck bool, out io.Writer) error {
	if skipCheck {
		fmt.Fprintln(out, "⚠ 已跳过写入前校验（--skip-check）：生成的配置未经验证")
		return nil
	}
	res, err := validateLinkOutput(configPath, raw, newPath)
	if err != nil {
		return fmt.Errorf("写入前校验失败，未改动任何文件: %w", err)
	}
	if len(res.added) > 0 {
		fmt.Fprintln(out, "生成的配置未通过校验：本次转换引入了原配置没有的问题，未改动任何文件。")
		fmt.Fprintln(out, "新增失败项：")
		for _, f := range res.added {
			fmt.Fprintf(out, "  %s\n", f)
		}
		return errors.New("生成的配置未通过校验（link 引入了新的问题），未改动任何文件")
	}
	if len(res.baseline) > 0 {
		fmt.Fprintln(out, "⚠ 警告：原配置在转换前就有以下问题（与本次转换无关，不阻止转换）：")
		const maxShown = 10
		for i, f := range res.baseline {
			if i == maxShown {
				fmt.Fprintf(out, "  …（还有 %d 条未显示）\n", len(res.baseline)-maxShown)
				break
			}
			fmt.Fprintf(out, "  %s\n", f)
		}
	}
	return nil
}

// validateAgentYML validates the generated agent.yml on its own. It is only
// needed when an agent.yml already exists: the temporary config used by
// validateLinkWrite resolves that file (agent.yml wins as a whole), so the new
// agent.yml would otherwise never be checked. Only a problem the old agent.yml
// did not have stops the write, exactly like validateLinkWrite.
func validateAgentYML(dir string, plan *linkPlan, skipCheck bool, out io.Writer) error {
	if skipCheck {
		return nil
	}
	tmp, err := os.CreateTemp(dir, ".link-agent-*.yml")
	if err != nil {
		return fmt.Errorf("创建 agent 校验文件失败: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.WriteString(plan.renderAgent()); err != nil {
		tmp.Close()
		return fmt.Errorf("写入 agent 校验文件失败: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("设置 agent 校验文件权限失败: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("关闭 agent 校验文件失败: %w", err)
	}

	oldPath := filepath.Join(dir, agentcfg.FileName)
	volatile := []string{oldPath, tmpPath}
	inOld := make(map[string]bool)
	for _, f := range agentYMLFailures(oldPath) {
		inOld[linkFailureKey(f, volatile...)] = true
	}
	var added []string
	for _, f := range agentYMLFailures(tmpPath) {
		if inOld[linkFailureKey(f, volatile...)] {
			continue
		}
		added = append(added, f)
	}
	if len(added) > 0 {
		fmt.Fprintln(out, "生成的 agent.yml 未通过校验：")
		for _, f := range added {
			fmt.Fprintf(out, "  %s\n", f)
		}
		return errors.New("生成的 agent.yml 未通过校验，未改动任何文件")
	}
	return nil
}

// agentYMLFailures runs the offline validation of one agent.yml and returns the
// failure items, in the same "✗" form `W1nCray check` prints. It reads the
// token file (so a bad mode is caught) but never prints the token.
func agentYMLFailures(path string) []string {
	cfg, err := agentcfg.Load(path)
	if err != nil {
		return []string{fmt.Sprintf("✗ agent.yml 解析失败（agent 将无法启动）: %v", err)}
	}
	if cfg == nil {
		return nil
	}
	resolveAgentPaths(cfg, filepath.Dir(path))
	var out []string
	if err := cfg.Validate(); err != nil {
		out = append(out, "✗ "+err.Error())
	}
	if cfg.Panel != nil && cfg.Panel.Enabled {
		if _, err := cfg.Panel.ResolveToken(); err != nil {
			out = append(out, "✗ "+err.Error())
		}
	}
	return append(out, linkPanelCertModeFailures(cfg.Panel)...)
}

// resolveAgentPaths applies the agent.yml path defaults the way
// panel.LoadConfig does, so the standalone validation of a staged file reads
// the same token file as the final one.
func resolveAgentPaths(cfg *agentcfg.Config, base string) {
	if cfg.StateDir == "" {
		cfg.StateDir = filepath.Join(base, "state")
	} else if !filepath.IsAbs(cfg.StateDir) {
		cfg.StateDir = filepath.Join(base, cfg.StateDir)
	}
	if cfg.Panel != nil && cfg.Panel.TokenFile != "" && !filepath.IsAbs(cfg.Panel.TokenFile) {
		cfg.Panel.TokenFile = filepath.Join(base, cfg.Panel.TokenFile)
	}
}

// writeBaselineCopy writes raw to a temporary file in the config's directory
// and returns its path and a cleanup function. It lives next to the converted
// file so the validation sees the same directory.
func writeBaselineCopy(configPath string, raw []byte) (string, func(), error) {
	f, err := os.CreateTemp(filepath.Dir(configPath), ".link-baseline-*.yml")
	if err != nil {
		return "", nil, fmt.Errorf("创建校验基线文件失败: %w", err)
	}
	path := f.Name()
	cleanup := func() { os.Remove(path) }
	if _, err := f.Write(raw); err != nil {
		f.Close()
		cleanup()
		return "", nil, fmt.Errorf("写入校验基线文件失败: %w", err)
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		cleanup()
		return "", nil, fmt.Errorf("设置校验基线文件权限失败: %w", err)
	}
	if err := f.Close(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("关闭校验基线文件失败: %w", err)
	}
	return path, cleanup, nil
}

var (
	linkTempFileRe = regexp.MustCompile(`\.link-[A-Za-z0-9._-]*\.yml`)
	linkBackupRe   = regexp.MustCompile(`\.bak-link-[0-9-]+`)
)

// linkFailureKey returns the stable comparison key of a failure item: the
// temporary names of this run (and any backup timestamp) are replaced, so the
// same pre-existing problem hashes equal on the baseline and on the converted
// config.
func linkFailureKey(text string, volatile ...string) string {
	s := strings.TrimSpace(text)
	for _, v := range volatile {
		if v == "" {
			continue
		}
		s = strings.ReplaceAll(s, v, "<config>")
		s = strings.ReplaceAll(s, filepath.ToSlash(v), "<config>")
	}
	s = linkTempFileRe.ReplaceAllString(s, "<config>")
	s = linkBackupRe.ReplaceAllString(s, "<backup>")
	return s
}

// dedupeFailures removes duplicate items, keeping the first occurrence.
func dedupeFailures(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, f := range in {
		key := strings.TrimSpace(f)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}

// runLink converts configPath in place. It never restarts the service.
func runLink(configPath string, opts linkOptions, out io.Writer) error {
	panelURL, err := normalizePanelURL(opts.Panel, opts.AllowHTTP)
	if err != nil {
		return err
	}
	if opts.Machine <= 0 {
		return errors.New("--machine 必须是正整数")
	}
	portLo, portHi, err := parsePortRange(opts.PortRange)
	if err != nil {
		return err
	}
	// The token is read (and validated) up front, but only ever written to the
	// token file; it must not reach the config, stdout or an error.
	token, err := resolveLinkToken(opts)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("读取配置 %s 失败: %w", configPath, err)
	}
	panelOrigin, ok := urlOrigin(panelURL)
	if !ok {
		return fmt.Errorf("--panel 不是合法 URL: %s", panelURL)
	}

	dir := filepath.Dir(configPath)
	tokenPath := filepath.Join(dir, "agent.token")
	stateDir := filepath.Join(dir, "state")

	plan, err := planLink(string(raw), configPath, opts, panelOrigin)
	if err != nil {
		return err
	}
	if len(plan.convertedIDs()) == 0 {
		fmt.Fprint(out, plan.text(tokenPath, ""))
		return errors.New("没有可转换的节点：所有节点的 ApiHost 与 --panel 不一致，或存在机器模式无法表达的本地覆盖")
	}
	plan.agentLines = plan.buildAgentYML(panelURL, tokenPath, stateDir, opts, portLo, portHi)

	fmt.Fprint(out, plan.text(tokenPath, ""))
	if opts.DryRun {
		fmt.Fprintln(out, "（dry-run：未写入任何文件）")
		printNextSteps(out, opts.Machine, plan.convertedIDs(), "", true)
		return nil
	}

	created, err := ensureTokenFile(tokenPath, token)
	if err != nil {
		return err
	}
	// Until the config is replaced, a token file created by this run is not
	// part of a finished conversion: remove it again on every failure path.
	cleanupToken := func() {
		if created {
			os.Remove(tokenPath)
		}
	}

	// Stage the config for the pre-write validation with the generated agent
	// section inlined as the Agent: block: the validation then checks the agent
	// configuration link is about to write even though it will live in
	// agent.yml. The staged file is thrown away; what replaces config.yml is
	// rendered again without the Agent block below.
	checkTmp, err := os.CreateTemp(dir, ".link-check-*.yml")
	if err != nil {
		cleanupToken()
		return fmt.Errorf("创建校验临时文件失败: %w", err)
	}
	checkPath := checkTmp.Name()
	defer os.Remove(checkPath)
	if _, err := checkTmp.WriteString(plan.renderForCheck()); err != nil {
		checkTmp.Close()
		cleanupToken()
		return fmt.Errorf("写入校验临时文件失败: %w", err)
	}
	if err := checkTmp.Chmod(0o600); err != nil {
		checkTmp.Close()
		cleanupToken()
		return fmt.Errorf("设置校验临时文件权限失败: %w", err)
	}
	if err := checkTmp.Close(); err != nil {
		cleanupToken()
		return fmt.Errorf("关闭校验临时文件失败: %w", err)
	}

	if err := validateLinkWrite(configPath, raw, checkPath, opts.SkipCheck, out); err != nil {
		cleanupToken()
		return err
	}
	// When an agent.yml is already there, the temporary config resolves that
	// file instead of the inlined block, so the new agent.yml is validated on
	// its own as well.
	if plan.agentExists {
		if err := validateAgentYML(dir, plan, opts.SkipCheck, out); err != nil {
			cleanupToken()
			return err
		}
	}

	// Stage the file that actually replaces config.yml (no Agent block).
	tmp, err := os.CreateTemp(dir, ".link-*.yml")
	if err != nil {
		cleanupToken()
		return fmt.Errorf("创建临时文件失败: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.WriteString(plan.render()); err != nil {
		tmp.Close()
		cleanupToken()
		return fmt.Errorf("写入临时文件失败: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		cleanupToken()
		return fmt.Errorf("设置临时文件权限失败: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanupToken()
		return fmt.Errorf("关闭临时文件失败: %w", err)
	}

	backupPath, err := backupConfig(configPath, raw, time.Now().Format("20060102-150405"))
	if err != nil {
		cleanupToken()
		return err
	}
	// agent.yml is written atomically (temporary file + rename) and an existing
	// one is backed up first (agentcfg.WriteFile owns both rules).
	agentBackup, err := agentcfg.WriteFile(plan.agentPath, []byte(plan.renderAgent()))
	if err != nil {
		cleanupToken()
		return fmt.Errorf("写入 %s 失败（%s 已备份到 %s）: %w", plan.agentPath, configPath, backupPath, err)
	}
	if err := os.Rename(tmpPath, configPath); err != nil {
		restoreAgentYML(plan.agentPath, agentBackup, plan.agentExists)
		cleanupToken()
		return fmt.Errorf("替换 %s 失败（原文件已备份到 %s）: %w", configPath, backupPath, err)
	}

	fmt.Fprintf(out, "已更新 %s（原文件备份 %s）\n", configPath, backupPath)
	if plan.agentExists {
		fmt.Fprintf(out, "已更新 %s（原文件备份 %s）\n", plan.agentPath, agentBackup)
	} else {
		fmt.Fprintf(out, "已写入 %s（0600）\n", plan.agentPath)
	}
	if created {
		fmt.Fprintf(out, "已写入 token 文件 %s（0600）\n", tokenPath)
	} else {
		fmt.Fprintf(out, "token 文件 %s 已存在且内容一致，未改动\n", tokenPath)
	}
	printNextSteps(out, opts.Machine, plan.convertedIDs(), backupPath, false)
	return nil
}

// restoreAgentYML puts the previous agent.yml back after a failed config.yml
// replacement, so the two files never describe different machines. It is a
// best-effort rollback on an error path: the backup itself is kept.
func restoreAgentYML(agentPath, agentBackup string, existed bool) {
	if !existed {
		os.Remove(agentPath)
		return
	}
	if agentBackup == "" {
		return
	}
	if data, err := os.ReadFile(agentBackup); err == nil {
		os.WriteFile(agentPath, data, 0o600)
	}
}

// printNextSteps prints the Chinese follow-up (never restarts anything).
func printNextSteps(out io.Writer, machineID int, ids []int, backupPath string, dryRun bool) {
	fmt.Fprintln(out, "下一步：")
	fmt.Fprintf(out, "  1. 在面板管理页 → W1nCray 服务器 → 机器 %d → 节点，绑定节点 %s（旧静态节点在绑定后仍可继续工作，绑定本身不影响它们）\n", machineID, joinIDs(ids))
	fmt.Fprintln(out, "  2. 然后执行 `W1nCray restart` 使机器模式生效")
	if dryRun {
		fmt.Fprintln(out, "  3. 回滚：恢复备份文件并重启（本次为 dry-run，未生成备份）")
	} else {
		fmt.Fprintf(out, "  3. 回滚：恢复备份文件 %s 并重启\n", backupPath)
	}
}

// ---- flag validation -----------------------------------------------------

// normalizePanelURL trims trailing slashes and applies the same URL rules as
// the panel client (https unless loopback or AllowInsecureHTTP).
func normalizePanelURL(raw string, allowHTTP bool) (string, error) {
	u := strings.TrimSpace(raw)
	if u == "" {
		return "", errors.New("--panel 不能为空")
	}
	u = strings.TrimRight(u, "/")
	parsed, err := url.Parse(u)
	if err != nil {
		return "", fmt.Errorf("--panel 不是合法 URL: %w", err)
	}
	if parsed.Host == "" {
		return "", errors.New("--panel 缺少主机名")
	}
	if parsed.User != nil {
		return "", errors.New("--panel 不能包含用户名或密码")
	}
	if _, err := panelclient.New(panelclient.Options{
		BaseURL:           u,
		MachineID:         1,
		Token:             "-",
		AllowInsecureHTTP: allowHTTP,
	}); err != nil {
		return "", fmt.Errorf("--panel: %s", strings.TrimPrefix(err.Error(), "panelclient: "))
	}
	return u, nil
}

// parsePortRange parses "LO-HI".
func parsePortRange(s string) (int, int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 20000, 40000, nil
	}
	lo, hi, ok := strings.Cut(s, "-")
	if !ok {
		return 0, 0, fmt.Errorf("--port-range 需要 LO-HI 形式（例如 20000-40000），收到: %s", s)
	}
	l, errLo := strconv.Atoi(strings.TrimSpace(lo))
	h, errHi := strconv.Atoi(strings.TrimSpace(hi))
	if errLo != nil || errHi != nil || l < 1 || h > 65535 || l > h {
		return 0, 0, fmt.Errorf("--port-range 非法（需 1-65535 且 LO<=HI）: %s", s)
	}
	return l, h, nil
}

// resolveLinkToken returns the machine token from --token or --token-file.
// The value is never included in an error.
func resolveLinkToken(opts linkOptions) (string, error) {
	switch {
	case opts.Token != "" && opts.TokenFile != "":
		return "", errors.New("--token 与 --token-file 只能提供一个")
	case opts.TokenFile != "":
		b, err := os.ReadFile(opts.TokenFile)
		if err != nil {
			return "", fmt.Errorf("读取 --token-file 失败: %w", err)
		}
		return cleanToken(string(b))
	case opts.Token != "":
		return cleanToken(opts.Token)
	default:
		return "", errors.New("缺少机器令牌：请用 --token 或 --token-file 提供")
	}
}

func cleanToken(s string) (string, error) {
	t := strings.TrimSpace(s)
	if t == "" {
		return "", errors.New("机器令牌为空")
	}
	if strings.ContainsAny(t, " \t\r\n") {
		return "", errors.New("机器令牌不能包含空白字符")
	}
	return t, nil
}

// urlOrigin renders the scheme://host[:port] of a URL, dropping the default
// port of the scheme so "https://h" and "https://h:443" compare equal.
func urlOrigin(raw string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", false
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", false
	}
	port := u.Port()
	if port == "" || (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		return scheme + "://" + host, true
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return scheme + "://" + host + ":" + port, true
}

// ---- token file ----------------------------------------------------------

// ensureTokenFile writes token to path with mode 0600. It returns whether the
// file was created; an existing file with different content is an error and is
// never overwritten.
func ensureTokenFile(path, token string) (created bool, err error) {
	if b, err := os.ReadFile(path); err == nil {
		if strings.TrimSpace(string(b)) == token {
			return false, nil
		}
		return false, fmt.Errorf("%s 已存在且内容不同，拒绝覆盖（请先手工处理该文件）", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("读取 %s 失败: %w", path, err)
	}
	old := setUmask(0o077)
	defer setUmask(old)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return false, fmt.Errorf("写入 %s 失败: %w", path, err)
	}
	if _, err := f.WriteString(token); err != nil {
		f.Close()
		os.Remove(path)
		return false, fmt.Errorf("写入 %s 失败: %w", path, err)
	}
	// The explicit chmod makes the mode 0600 regardless of the process umask.
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		os.Remove(path)
		return false, fmt.Errorf("设置 %s 权限失败: %w", path, err)
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return false, fmt.Errorf("关闭 %s 失败: %w", path, err)
	}
	return true, nil
}

// backupConfig copies raw to <config>.bak-link-<ts> (0600) and returns the path
// actually used.
func backupConfig(configPath string, raw []byte, ts string) (string, error) {
	base := configPath + ".bak-link-" + ts
	for i := 0; ; i++ {
		p := base
		if i > 0 {
			p = fmt.Sprintf("%s-%d", base, i)
		}
		f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("创建备份 %s 失败: %w", p, err)
		}
		if _, err := f.Write(raw); err != nil {
			f.Close()
			os.Remove(p)
			return "", fmt.Errorf("写入备份 %s 失败: %w", p, err)
		}
		if err := f.Chmod(0o600); err != nil {
			f.Close()
			os.Remove(p)
			return "", fmt.Errorf("设置备份 %s 权限失败: %w", p, err)
		}
		if err := f.Close(); err != nil {
			os.Remove(p)
			return "", fmt.Errorf("关闭备份 %s 失败: %w", p, err)
		}
		return p, nil
	}
}

// ---- line-based YAML parsing --------------------------------------------

// linkLine is one line of the config file.
type linkLine struct {
	text    string
	indent  int
	blank   bool
	comment bool
}

func makeLine(s string) linkLine {
	l := linkLine{text: s}
	if strings.TrimSpace(s) == "" {
		l.blank = true
		l.indent = -1
		return l
	}
	t := strings.TrimLeft(s, " ")
	l.indent = len(s) - len(t)
	// A line whose content is only an inline comment is a comment line, so it
	// can never be mistaken for a key.
	l.comment = !hasContent(s)
	return l
}

// stripInlineComment returns text with a YAML inline comment removed: a '#'
// starts a comment at the beginning of the text or when preceded by
// whitespace, and never inside a single- or double-quoted scalar. Everything
// from that '#' on is dropped.
//
// It is the one place that decides where an inline value ends. A real config
// line such as
//
//	RuleListPath: # /etc/W1nCray/rulelist Path to local rulelist file
//
// therefore yields an empty value instead of treating the comment text as the
// value. Callers either decode the result (scalarValue) or only ask whether
// anything is left (hasContent).
func stripInlineComment(text string) string {
	var quote byte
	for i := 0; i < len(text); i++ {
		c := text[i]
		if quote != 0 {
			switch {
			case quote == '"' && c == '\\':
				i++ // the next byte is escaped, so it cannot close the scalar
			case c == quote:
				if quote == '\'' && i+1 < len(text) && text[i+1] == '\'' {
					i++ // '' is an escaped single quote
					continue
				}
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case '#':
			if i == 0 || text[i-1] == ' ' || text[i-1] == '\t' {
				return text[:i]
			}
		}
	}
	return text
}

// hasContent reports whether text holds anything but an inline comment.
func hasContent(text string) bool {
	return strings.TrimSpace(stripInlineComment(text)) != ""
}

var keyRe = regexp.MustCompile(`^([A-Za-z0-9_.\-]+):(\s|$)`)

// lineKey returns the "Key: value" of a line, looking through a leading "- ".
func lineKey(l linkLine) (key, val string, ok bool) {
	if l.blank || l.comment {
		return "", "", false
	}
	rest := l.text[l.indent:]
	if strings.HasPrefix(rest, "- ") {
		rest = rest[2:]
	} else if rest == "-" {
		return "", "", false
	}
	m := keyRe.FindStringSubmatch(rest)
	if m == nil {
		return "", "", false
	}
	return m[1], strings.TrimSpace(rest[len(m[1])+1:]), true
}

// itemOf reports whether a line starts a sequence entry.
func itemOf(l linkLine) bool {
	if l.blank || l.comment {
		return false
	}
	rest := l.text[l.indent:]
	return rest == "-" || strings.HasPrefix(rest, "- ")
}

// topLevelKey finds a key at indentation 0.
func topLevelKey(lines []linkLine, name string) (int, bool) {
	for i, l := range lines {
		if l.indent != 0 || l.blank || l.comment {
			continue
		}
		if k, _, ok := lineKey(l); ok && k == name {
			return i, true
		}
	}
	return -1, false
}

// blockEnd returns the index just past the lines belonging to the key at
// keyIdx (blank lines and comments are transparent; a sequence item at the
// key's own indentation still belongs to it).
func blockEnd(lines []linkLine, keyIdx, limit, baseIndent int) int {
	last := keyIdx
	for j := keyIdx + 1; j < limit; j++ {
		l := lines[j]
		if l.blank {
			continue
		}
		if l.comment {
			if l.indent > baseIndent {
				last = j
			}
			continue
		}
		if l.indent > baseIndent || (l.indent == baseIndent && itemOf(l)) {
			last = j
			continue
		}
		break
	}
	return last + 1
}

// entryStarts lists the sequence entry lines of a block.
func entryStarts(lines []linkLine, from, to int) []int {
	var starts []int
	ind := -1
	for i := from; i < to; i++ {
		if !itemOf(lines[i]) {
			continue
		}
		if ind == -1 {
			ind = lines[i].indent
		}
		if lines[i].indent == ind {
			starts = append(starts, i)
		}
	}
	return starts
}

// entryRange returns the index just past the last content line of the entry
// starting at start. Trailing blank lines and comments at the entry's own
// indentation (which belong to the gap or the next entry) are excluded.
func entryRange(lines []linkLine, start, limit, entryIndent int) int {
	last := start
	for j := start + 1; j < limit; j++ {
		l := lines[j]
		if l.blank {
			continue
		}
		if l.comment {
			if l.indent > entryIndent {
				last = j
			}
			continue
		}
		if l.indent > entryIndent {
			last = j
			continue
		}
		break
	}
	return last + 1
}

// scalarValue decodes a YAML scalar written inline: an inline comment is
// stripped first, then the surrounding whitespace and, for a quoted scalar, the
// quotes. A value that is empty or holds only a comment decodes to "".
func scalarValue(raw string) string {
	s := strings.TrimSpace(stripInlineComment(raw))
	if s == "" {
		return ""
	}
	switch s[0] {
	case '"':
		var b strings.Builder
		for i := 1; i < len(s); i++ {
			c := s[i]
			if c == '\\' && i+1 < len(s) {
				i++
				switch s[i] {
				case 'n':
					b.WriteByte('\n')
				case 't':
					b.WriteByte('\t')
				case 'r':
					b.WriteByte('\r')
				default:
					b.WriteByte(s[i])
				}
				continue
			}
			if c == '"' {
				return b.String()
			}
			b.WriteByte(c)
		}
		return b.String()
	case '\'':
		var b strings.Builder
		for i := 1; i < len(s); i++ {
			if s[i] == '\'' {
				if i+1 < len(s) && s[i+1] == '\'' {
					b.WriteByte('\'')
					i++
					continue
				}
				return b.String()
			}
			b.WriteByte(s[i])
		}
		return b.String()
	}
	return s
}

// parseFlowMap parses "{a: 1, b: two}" into a map. It is only used to read an
// inline ApiConfig; an inline ControllerConfig is not converted.
func parseFlowMap(s string) map[string]string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "{") {
		return nil
	}
	s = strings.TrimPrefix(s, "{")
	if i := strings.LastIndex(s, "}"); i >= 0 {
		s = s[:i]
	}
	var parts []string
	depth, start := 0, 0
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if c == '\\' && quote == '"' {
				i++
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case '{', '[':
			depth++
		case '}', ']':
			depth--
		case ',':
			if depth == 0 {
				parts = append(parts, s[start:i])
				start = i + 1
			}
		}
	}
	parts = append(parts, s[start:])
	out := make(map[string]string, len(parts))
	for _, p := range parts {
		k, v, ok := strings.Cut(p, ":")
		if !ok {
			continue
		}
		out[strings.TrimSpace(k)] = scalarValue(v)
	}
	return out
}

// ---- the conversion plan -------------------------------------------------

type linkNode struct {
	id         int
	label      string
	apiHost    string
	entryStart int
	entryEnd   int
	ccLines    []string
	convert    bool
	reason     string
}

type linkOverride struct {
	id    int
	lines []string
}

type linkPlan struct {
	raw         []string
	eol         string
	nodes       []*linkNode
	configPath  string
	machineID   int
	date        string
	agentLines  []string
	convertedAt map[int]*linkNode

	// agent.yml layout. agentPath is where the agent section is written,
	// agentExists says whether it was already there (only --force may replace
	// it) and hasAgentBlock/agentStart/agentEnd describe the config.yml
	// "Agent:" block that is migrated into agent.yml. migrated holds the
	// dedented block body without the sections link writes itself, and
	// panelExtras the Panel keys link does not own.
	agentPath     string
	agentExists   bool
	hasAgentBlock bool
	agentStart    int
	agentEnd      int
	migrated      []string
	panelExtras   []string
}

func splitRaw(raw string) ([]string, string) {
	eol := "\n"
	if strings.Contains(raw, "\r\n") {
		eol = "\r\n"
	}
	body := raw
	if strings.HasSuffix(body, eol) {
		body = body[:len(body)-len(eol)]
	}
	if body == "" {
		return nil, eol
	}
	return strings.Split(body, eol), eol
}

func planLink(raw, configPath string, opts linkOptions, panelOrigin string) (*linkPlan, error) {
	rawLines, eol := splitRaw(raw)
	lines := make([]linkLine, len(rawLines))
	for i, s := range rawLines {
		lines[i] = makeLine(s)
	}
	dir := filepath.Dir(configPath)
	agentPath := filepath.Join(dir, agentcfg.FileName)

	// Refuse to touch a config that was already converted. This runs before the
	// entry check so a fully converted config (its Nodes are all commented out)
	// still reports the clear "already converted" error instead of "no Nodes
	// entries".
	if !opts.Force && strings.Contains(raw, "#LINKED-") {
		return nil, errors.New("配置已经转换过（发现 #LINKED- 标记），拒绝覆盖；如需重做请先恢复备份")
	}
	// An existing agent.yml is the live agent configuration: overwriting it
	// without --force would silently discard it. --force backs it up first.
	agentExists := false
	switch _, err := os.Stat(agentPath); {
	case err == nil:
		agentExists = true
	case errors.Is(err, os.ErrNotExist):
	default:
		return nil, fmt.Errorf("检查 %s 失败: %w", agentPath, err)
	}
	if agentExists && !opts.Force {
		return nil, fmt.Errorf("%s 已存在：已有关联配置，拒绝覆盖；如需重做请先恢复备份，或用 --force 覆盖（会先备份）", agentPath)
	}

	nodesIdx, ok := topLevelKey(lines, "Nodes")
	if !ok {
		return nil, errors.New("配置里没有 Nodes: 段")
	}
	nodesEnd := blockEnd(lines, nodesIdx, len(lines), 0)

	// The old single-file layout keeps the agent configuration in config.yml.
	// It is migrated to agent.yml instead of being refused, so an existing
	// deployment moves to the separated layout without a manual merge.
	agentIdx, hasAgent := topLevelKey(lines, "Agent")
	agentEnd := -1
	if hasAgent {
		agentEnd = blockEnd(lines, agentIdx, len(lines), 0)
	}

	starts := entryStarts(lines, nodesIdx+1, nodesEnd)
	if len(starts) == 0 {
		return nil, errors.New("Nodes: 段里没有节点条目")
	}

	p := &linkPlan{
		raw:           rawLines,
		eol:           eol,
		configPath:    configPath,
		machineID:     opts.Machine,
		date:          time.Now().Format("2006-01-02"),
		convertedAt:   make(map[int]*linkNode),
		agentPath:     agentPath,
		agentExists:   agentExists,
		hasAgentBlock: hasAgent,
		agentStart:    agentIdx,
		agentEnd:      agentEnd,
	}
	if hasAgent {
		p.migrated, p.panelExtras = migrateAgentBlock(lines, agentIdx, agentEnd, opts.NoTerminal)
	}
	seen := make(map[int]bool)
	for _, st := range starts {
		en := entryRange(lines, st, nodesEnd, lines[st].indent)
		n := parseLinkNode(lines, rawLines, st, en, panelOrigin, opts.IgnoreAPIOverrides)
		if n.id > 0 && n.convert {
			if seen[n.id] {
				return nil, fmt.Errorf("转换后节点 %d 会出现两次（NodeControllers 的键必须唯一），请先手工处理", n.id)
			}
			seen[n.id] = true
			p.convertedAt[st] = n
		}
		p.nodes = append(p.nodes, n)
	}
	return p, nil
}

// migrateAgentBlock turns the config.yml "Agent:" block into the root of
// agent.yml: the body is dedented and the sub-sections link writes itself
// (Panel, and Terminal when --noterminal is given) are dropped, so the
// operator's local settings survive without a duplicated key. Enabled: true is
// ensured: a machine that runs link is a machine the agent has to be on for.
//
// The Panel block is regenerated from the flags, but its keys link does not own
// (ManifestSync, the intervals, the NodeController template, ...) are returned
// separately so the caller can put them back inside the new Panel section
// instead of silently resetting them to their defaults.
func migrateAgentBlock(lines []linkLine, start, end int, dropTerminal bool) (body, panelExtras []string) {
	// The block's direct children share one indentation; it is the dedent base
	// for agent.yml's root.
	base := -1
	for i := start + 1; i < end; i++ {
		if strings.TrimSpace(lines[i].text) == "" {
			continue
		}
		if lines[i].indent > lines[start].indent && (base < 0 || lines[i].indent < base) {
			base = lines[i].indent
		}
	}
	if base < 0 {
		base = lines[start].indent + 2
	}

	// The Panel keys link writes itself; everything else in the block is the
	// operator's.
	managed := map[string]bool{
		"Enabled": true, "URL": true, "MachineID": true, "Token": true,
		"TokenFile": true, "AllowInsecureHTTP": true, "MachineNodes": true,
		"NodeControllers": true,
	}
	skip := make(map[int]bool)
	for i := start + 1; i < end; i++ {
		k, _, ok := lineKey(lines[i])
		if !ok {
			continue
		}
		switch {
		case k == "Panel":
			panelEnd := blockEnd(lines, i, end, lines[i].indent)
			skip[i] = true
			childIndent := -1
			for j := i + 1; j < panelEnd; j++ {
				if strings.TrimSpace(lines[j].text) == "" {
					continue
				}
				if childIndent < 0 && lines[j].indent > lines[i].indent {
					childIndent = lines[j].indent
				}
				if lines[j].indent != childIndent {
					continue
				}
				if k2, _, ok2 := lineKey(lines[j]); ok2 && managed[k2] {
					for m := j; m < blockEnd(lines, j, panelEnd, lines[j].indent); m++ {
						skip[m] = true
					}
				}
			}
		case dropTerminal && k == "Terminal":
			for j := i; j < blockEnd(lines, i, end, lines[i].indent); j++ {
				skip[j] = true
			}
		}
	}

	// Panel extras are collected with the same dedent as the body, so they sit
	// at the right indentation inside the generated Panel section.
	panelStart, panelEnd := -1, -1
	for i := start + 1; i < end; i++ {
		if k, _, ok := lineKey(lines[i]); ok && k == "Panel" && lines[i].indent == base {
			panelStart, panelEnd = i, blockEnd(lines, i, end, lines[i].indent)
			break
		}
	}
	if panelStart >= 0 {
		for i := panelStart + 1; i < panelEnd; i++ {
			if skip[i] || strings.TrimSpace(lines[i].text) == "" {
				continue
			}
			panelExtras = append(panelExtras, dedent(lines[i].text, base))
		}
	}

	for i := start + 1; i < end; i++ {
		if skip[i] {
			continue
		}
		if strings.TrimSpace(lines[i].text) == "" {
			body = append(body, "")
			continue
		}
		body = append(body, dedent(lines[i].text, base))
	}
	enabledAt := -1
	for i, l := range body {
		ml := makeLine(l)
		if ml.indent != 0 {
			continue
		}
		if k, _, ok := lineKey(ml); ok && k == "Enabled" {
			enabledAt = i
			break
		}
	}
	if enabledAt >= 0 {
		body[enabledAt] = "Enabled: true"
	} else {
		body = append([]string{"Enabled: true"}, body...)
	}
	return body, panelExtras
}

// dedent removes up to n leading spaces from a line. A blank line stays blank
// and a line that is less indented than n loses only the spaces it has.
func dedent(line string, n int) string {
	if strings.TrimSpace(line) == "" {
		return ""
	}
	i := 0
	for i < n && i < len(line) && line[i] == ' ' {
		i++
	}
	return line[i:]
}

// parseLinkNode reads one Nodes entry and decides whether it is converted.
func parseLinkNode(lines []linkLine, raw []string, start, end int, panelOrigin string, ignoreOverrides bool) *linkNode {
	n := &linkNode{entryStart: start, entryEnd: end}
	apiIdx, ccIdx := -1, -1
	for i := start; i < end; i++ {
		k, _, ok := lineKey(lines[i])
		if !ok {
			continue
		}
		if k == "ApiConfig" && apiIdx == -1 {
			apiIdx = i
		}
		if k == "ControllerConfig" && ccIdx == -1 {
			ccIdx = i
		}
	}

	var flow map[string]string
	apiEnd := -1
	if apiIdx >= 0 {
		_, val, _ := lineKey(lines[apiIdx])
		if flowVal := scalarValue(val); strings.HasPrefix(flowVal, "{") {
			flow = parseFlowMap(flowVal)
		} else {
			apiEnd = blockEnd(lines, apiIdx, end, lines[apiIdx].indent)
		}
	}
	get := func(name string) (string, bool) {
		if flow != nil {
			v, ok := flow[name]
			return v, ok
		}
		if apiIdx < 0 || apiEnd < 0 {
			return "", false
		}
		for j := apiIdx; j < apiEnd; j++ {
			if k, v, ok := lineKey(lines[j]); ok && k == name {
				return scalarValue(v), true
			}
		}
		return "", false
	}

	apiHost, _ := get("ApiHost")
	n.apiHost = apiHost
	idRaw, _ := get("NodeID")
	id, _ := strconv.Atoi(strings.TrimSpace(idRaw))
	if id <= 0 {
		n.label = "节点（缺少 NodeID）"
		n.reason = "缺少或非法的 NodeID"
		return n
	}
	n.id = id
	n.label = fmt.Sprintf("节点 %d", id)
	if apiHost == "" {
		n.reason = "缺少 ApiHost"
		return n
	}
	origin, ok := urlOrigin(apiHost)
	if !ok {
		n.reason = fmt.Sprintf("ApiHost %q 不是合法 URL", apiHost)
		return n
	}
	if origin != panelOrigin {
		n.reason = fmt.Sprintf("ApiHost %s 与 --panel %s 不一致（保持静态）", origin, panelOrigin)
		return n
	}
	if reason := apiOverrideReason(get); reason != "" && !ignoreOverrides {
		n.reason = reason + "（加 --ignore-api-overrides 可强制转换）"
		return n
	}
	if ccIdx < 0 {
		n.convert = true
		return n
	}
	if _, val, _ := lineKey(lines[ccIdx]); isInlineMapping(val) {
		n.reason = "ControllerConfig 是内联写法，无法安全迁移（请改为块状）"
		return n
	}
	ccEnd := blockEnd(lines, ccIdx, end, lines[ccIdx].indent)
	copied := append([]string(nil), raw[ccIdx+1:ccEnd]...)
	if hasYAMLContent(copied) {
		n.ccLines = copied
	}
	n.convert = true
	return n
}

// apiOverrideReason reports a local ApiConfig override machine mode cannot
// express ("" when there is none).
func apiOverrideReason(get func(string) (string, bool)) string {
	if v, ok := get("SpeedLimit"); ok && strings.TrimSpace(v) != "" {
		f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err != nil || f > 0 {
			return "ApiConfig.SpeedLimit > 0（机器模式无法表达本地限速）"
		}
	}
	if v, ok := get("DeviceLimit"); ok && strings.TrimSpace(v) != "" {
		d, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil || d > 0 {
			return "ApiConfig.DeviceLimit > 0（机器模式无法表达本地设备数限制）"
		}
	}
	if v, ok := get("RuleListPath"); ok && strings.TrimSpace(v) != "" {
		return "ApiConfig.RuleListPath 非空（机器模式无法表达本地规则文件）"
	}
	return ""
}

func isInlineMapping(val string) bool {
	s := scalarValue(val)
	return s != "" && s != "{}"
}

func hasYAMLContent(lines []string) bool {
	for _, l := range lines {
		if hasContent(l) {
			return true
		}
	}
	return false
}

// convertedIDs returns the ids of the converted nodes, sorted.
func (p *linkPlan) convertedIDs() []int {
	var ids []int
	for _, n := range p.nodes {
		if n.convert {
			ids = append(ids, n.id)
		}
	}
	sort.Ints(ids)
	return ids
}

// overrides returns the NodeControllers entries (ids sorted). The lines are the
// verbatim ControllerConfig body of the node, at the indentation it had under
// Nodes; the writer indents them for its target file.
func (p *linkPlan) overrides() []linkOverride {
	var ids []int
	for _, n := range p.nodes {
		if n.convert && len(n.ccLines) > 0 {
			ids = append(ids, n.id)
		}
	}
	sort.Ints(ids)
	out := make([]linkOverride, 0, len(ids))
	for _, id := range ids {
		for _, n := range p.nodes {
			if n.convert && n.id == id && len(n.ccLines) > 0 {
				out = append(out, linkOverride{id: id, lines: n.ccLines})
				break
			}
		}
	}
	return out
}

// render rebuilds config.yml: converted entries are commented out and the old
// Agent block is replaced by a one-line comment that points at agent.yml.
// Nothing else is touched.
func (p *linkPlan) render() string {
	var out []string
	for i := 0; i < len(p.raw); {
		if p.hasAgentBlock && i == p.agentStart {
			out = append(out, fmt.Sprintf("# Agent: 段已迁移到 %s（W1nCray link %s）；本文件不再包含 Agent 配置", agentcfg.FileName, p.date))
			i = p.agentEnd
			continue
		}
		n, ok := p.convertedAt[i]
		if !ok {
			out = append(out, p.raw[i])
			i++
			continue
		}
		out = append(out, fmt.Sprintf("#LINKED-%s node %d now runs in machine mode (Agent.Panel, machine %d); original static entry kept below for rollback", p.date, n.id, p.machineID))
		for j := n.entryStart; j < n.entryEnd; j++ {
			out = append(out, "#"+p.raw[j])
		}
		i = n.entryEnd
	}
	if len(out) == 0 {
		return p.eol
	}
	return strings.Join(out, p.eol) + p.eol
}

// renderForCheck is render with the generated agent section inlined as the
// Agent: block. The pre-write validation loads this file, so it checks the
// agent configuration link is about to write even though it will live in
// agent.yml afterwards.
func (p *linkPlan) renderForCheck() string {
	lines := append([]string{"Agent:"}, shiftRight(p.agentLines, 2)...)
	return p.render() + p.eol + strings.Join(lines, p.eol) + p.eol
}

// renderAgent renders agent.yml: the root of the file is the agent
// configuration itself (no "Agent:" wrapper), so a field name means the same
// thing in both files (ruling 1).
func (p *linkPlan) renderAgent() string {
	return strings.Join(p.agentLines, p.eol) + p.eol
}

// text renders the plan report.
func (p *linkPlan) text(tokenPath, backupPath string) string {
	var b strings.Builder
	b.WriteString("转换计划：\n")
	if ids := p.convertedIDs(); len(ids) > 0 {
		fmt.Fprintf(&b, "  将转换的节点: %s\n", joinIDs(ids))
	}
	var skipped []string
	for _, n := range p.nodes {
		if n.convert {
			continue
		}
		skipped = append(skipped, fmt.Sprintf("    - %s: %s", n.label, n.reason))
	}
	if len(skipped) > 0 {
		b.WriteString("  跳过的节点:\n")
		for _, s := range skipped {
			b.WriteString(s + "\n")
		}
	}
	fmt.Fprintf(&b, "  配置文件: %s\n", p.configPath)
	fmt.Fprintf(&b, "  agent 配置: %s\n", p.agentPath)
	if p.hasAgentBlock {
		fmt.Fprintf(&b, "    config.yml 的 Agent: 段将迁移到 agent.yml，原处留一行注释\n")
	}
	if p.agentExists {
		fmt.Fprintf(&b, "    agent.yml 已存在：先备份再覆盖（--force）\n")
	}
	if backupPath == "" {
		backupPath = p.configPath + ".bak-link-<时间戳>"
	}
	fmt.Fprintf(&b, "  备份文件: %s\n", backupPath)
	fmt.Fprintf(&b, "  token 文件: %s\n", tokenPath)
	return b.String()
}

// ---- output helpers ------------------------------------------------------

func shiftRight(lines []string, n int) []string {
	out := make([]string, len(lines))
	pad := strings.Repeat(" ", n)
	for i, l := range lines {
		if strings.TrimSpace(l) == "" {
			out[i] = ""
			continue
		}
		out[i] = pad + l
	}
	return out
}

// buildAgentYML returns the agent.yml lines: the operator's migrated Agent
// block when config.yml still had one, plus the panel link and the local
// terminal switch this run writes.
func (p *linkPlan) buildAgentYML(panelURL, tokenPath, stateDir string, opts linkOptions, portLo, portHi int) []string {
	ls := []string{
		"# W1nCray agent configuration (agent.yml).",
		"# This file wins as a whole over the Agent: block of config.yml, which is ignored.",
	}
	if p.hasAgentBlock {
		ls = append(ls, fmt.Sprintf("# The Agent: block of config.yml was migrated here by `W1nCray link` on %s.", p.date))
	} else {
		ls = append(ls, fmt.Sprintf("# Written by `W1nCray link` on %s.", p.date))
	}
	ls = append(ls, "# The interactive terminal is ON by default; Terminal: {Enabled: false} turns it off locally.")
	ls = append(ls, "")
	if p.hasAgentBlock {
		ls = append(ls, p.migrated...)
	} else {
		ls = append(ls, "Enabled: true")
		ls = append(ls, "StateDir: "+yamlDQ(stateDir))
		ls = append(ls, "Policy:")
		ls = append(ls, `  AllowListen: ["0.0.0.0"]`)
		ls = append(ls, fmt.Sprintf("  PortRange: [%d, %d]", portLo, portHi))
	}
	if opts.NoTerminal {
		ls = append(ls, "Terminal: {Enabled: false}")
	}
	ls = append(ls, buildPanelLines(panelURL, tokenPath, opts.Machine, opts.AllowHTTP, p.panelExtras, p.overrides())...)
	return ls
}

// buildPanelLines renders the Panel section at agent.yml's root indentation.
// extras are the migrated Panel keys link does not own (ManifestSync, the
// intervals, the NodeController template, ...); they keep their relative
// indentation and are written before the generated NodeControllers.
func buildPanelLines(panelURL, tokenPath string, machineID int, allowHTTP bool, extras []string, overrides []linkOverride) []string {
	ls := []string{
		"Panel:",
		"  Enabled: true",
		"  URL: " + yamlDQ(panelURL),
		fmt.Sprintf("  MachineID: %d", machineID),
		"  TokenFile: " + yamlDQ(tokenPath),
	}
	if allowHTTP {
		ls = append(ls, "  AllowInsecureHTTP: true")
	}
	ls = append(ls, "  MachineNodes: true")
	ls = append(ls, extras...)
	if len(overrides) == 0 {
		ls = append(ls, "  NodeControllers: {}")
		return ls
	}
	ls = append(ls, "  NodeControllers:")
	for _, ov := range overrides {
		ls = append(ls, fmt.Sprintf("    %d:", ov.id))
		ls = append(ls, ov.lines...)
	}
	return ls
}

// yamlDQ renders a string as a YAML double-quoted scalar.
func yamlDQ(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(&b, `\x%02x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

func joinIDs(ids []int) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = strconv.Itoa(id)
	}
	return strings.Join(parts, ", ")
}
