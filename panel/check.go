package panel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	xlog "github.com/xtls/xray-core/common/log"

	"github.com/W1nCwC/W1nCray/agent/agentcfg"
	"github.com/W1nCwC/W1nCray/agent/panelclient"
	"github.com/W1nCwC/W1nCray/api/xboard"
	"github.com/W1nCwC/W1nCray/common/cert"
	"github.com/W1nCwC/W1nCray/core"
	"github.com/W1nCwC/W1nCray/node"
)

// Check validates a config file without serving traffic. Offline it checks
// the config and every referenced JSON file with the Xray kernel; online it
// also fetches each node from the panel and builds its inbound and rules.
func Check(path string, online bool, w io.Writer) error {
	_, err := CheckReport(path, online, w)
	return err
}

// CheckReport runs exactly the same validation as Check. In addition to the
// error Check returns it reports the individual failure items Check found: the
// lines it prints with a "✗" (when the config cannot even be loaded, the
// loader's error is the only item). Everything CheckReport writes to w is byte
// for byte what Check writes, so `W1nCray check` keeps its output and exit
// code.
//
// The item texts are meant to be compared between two runs of the same
// machine: callers that diff them should normalise the volatile parts of a
// path (temporary file names, timestamps) first.
func CheckReport(path string, online bool, w io.Writer) ([]string, error) {
	rec := &failureRecorder{w: w}
	// agent.yml is reported first: it takes part in LoadConfig, so a broken one
	// stops the service from starting and must be on the first screen (R5).
	ymlErr := checkAgentYML(rec, path)
	cfg, err := LoadConfig(path)
	if err != nil {
		if ymlErr != nil {
			// The failing file was already named on the first screen.
			return rec.items(), err
		}
		return []string{err.Error()}, err
	}
	fmt.Fprintf(rec, "配置文件: %s（%d 个静态节点）\n", path, len(cfg.NodesConfig))
	failed := false
	agentOK := true
	if cfg.Agent != nil && cfg.Agent.Enabled {
		if err := checkAgent(rec, cfg, online); err != nil {
			failed, agentOK = true, false
		}
	}
	// Machine mode: the node list comes from the panel. Only --online talks to
	// it; offline the section just says where the nodes come from.
	if agentOK {
		if pc := machinePanel(cfg); pc != nil {
			if err := checkMachineNodes(rec, pc, online); err != nil {
				failed = true
			}
		}
	}
	quietKernelLog()

	var ns []core.NameServer
	nodePorts := map[int]string{}
	if online {
		certs := cert.NewManager(certDir(path, cfg))
		for _, nc := range cfg.NodesConfig {
			ctl := node.New(node.Options{API: nc.ApiConfig, Config: nc.ControllerConfig, Certs: certs, Reload: func(string) {}})
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			summary, err := ctl.Check(ctx)
			cancel()
			if err != nil {
				failed = true
				fmt.Fprintf(rec, "  ✗ %s: %v\n", ctl.Tag(), err)
				continue
			}
			fmt.Fprintf(rec, "  ✓ %s: %s\n", ctl.Tag(), summary)
			ns = append(ns, ctl.NameServers()...)
			if p := ctl.PendingPort(); p > 0 {
				if _, taken := nodePorts[p]; !taken {
					nodePorts[p] = ctl.Tag()
				}
			}
		}
	}

	reportLegacyTags(rec, cfg, nodePorts, online)
	opts := coreOptions(cfg, ns)
	// Keep the kernel's debug/info output out of the check report.
	if opts.LogLevel == "debug" || opts.LogLevel == "info" {
		opts.LogLevel = "warning"
	}
	opts.AccessPath, opts.ErrorPath = "", ""
	if errs := core.CheckFiles(opts); len(errs) > 0 {
		failed = true
		for _, e := range errs {
			fmt.Fprintf(rec, "  ✗ %v\n", e)
		}
	}
	if c, err := core.New(opts); err != nil {
		failed = true
		fmt.Fprintf(rec, "  ✗ Xray 实例: %v\n", err)
	} else {
		c.Close()
		fmt.Fprintln(rec, "  ✓ Xray 实例构建成功（dns/route/自定义出入站）")
	}
	if failed {
		return rec.items(), errors.New("检查未通过")
	}
	fmt.Fprintln(rec, "检查通过")
	return nil, nil
}

// failureRecorder forwards everything to the wrapped writer and records the
// lines Check marks as failures ("  ✗ …"). It is what lets CheckReport return
// the failure items without changing a single byte of the report.
type failureRecorder struct {
	w    io.Writer
	rest []byte
	got  []string
}

func (r *failureRecorder) Write(p []byte) (int, error) {
	n, err := r.w.Write(p)
	if n > 0 {
		r.rest = append(r.rest, p[:n]...)
		for {
			i := bytes.IndexByte(r.rest, '\n')
			if i < 0 {
				break
			}
			r.record(string(r.rest[:i]))
			r.rest = r.rest[i+1:]
		}
	}
	return n, err
}

// record keeps a failure line. The marker is a full-width "✗", exactly the one
// every failure message in this file prints.
func (r *failureRecorder) record(line string) {
	s := strings.TrimSpace(line)
	if strings.HasPrefix(s, "✗") {
		r.got = append(r.got, s)
	}
}

// items returns the recorded failure items. A trailing partial line (a write
// without its final newline) is recorded too, so nothing is lost.
func (r *failureRecorder) items() []string {
	if len(r.rest) > 0 {
		r.record(string(r.rest))
		r.rest = nil
	}
	return r.got
}

// checkAgentYML reports agent.yml before anything else. The file is part of
// LoadConfig, so a broken one stops the service from starting: its parse error
// belongs on the first screen, and the operator must also be able to see that
// it is the file in charge (design R5, ruling 1). It prints nothing for the old
// single-file layout, so existing reports are unchanged.
func checkAgentYML(w io.Writer, configPath string) error {
	path := filepath.Join(filepath.Dir(configPath), agentcfg.FileName)
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	fmt.Fprintf(w, "  agent.yml: %s\n", path)
	cfg, err := agentcfg.Load(path)
	if err != nil {
		fmt.Fprintf(w, "  ✗ agent.yml 解析失败（agent 将无法启动）: %v\n", err)
		return err
	}
	if cfg == nil {
		return nil
	}
	// config.yml may still carry the old Agent block; it is ignored as a whole.
	// A config.yml that does not load is reported by LoadConfig below, so the
	// hint is simply skipped here.
	if other, err := loadConfigFile(configPath); err == nil && other.Agent != nil {
		fmt.Fprintf(w, "  ! %s 的 Agent 段被 agent.yml 覆盖（已忽略）\n", configPath)
	}
	fmt.Fprintf(w, "  ✓ agent.yml 已解析（生效来源 %s）\n", path)
	return nil
}

// checkAgent reports the agent section and verifies the files it references.
// A missing manifest is not fatal (only the builtin xray engine runs then),
// but a configured path that does not exist is.
func checkAgent(w io.Writer, cfg *Config, online bool) error {
	a := cfg.Agent
	source := cfg.AgentSourcePath()
	if source == "" {
		source = "未知"
	}
	fmt.Fprintf(w, "  Agent: 已启用（来源 %s，状态目录 %s，内核目录 %s）\n", source, a.StateDir, a.KernelsDir)
	if a.ManifestPath == "" {
		fmt.Fprintln(w, "  ! Agent.ManifestPath 未设置：仅内嵌 xray 引擎可用")
	} else if _, err := os.Stat(a.ManifestPath); err != nil {
		fmt.Fprintf(w, "  ✗ Agent.ManifestPath: %v\n", err)
		return err
	} else {
		fmt.Fprintf(w, "  ✓ Agent.ManifestPath: %s\n", a.ManifestPath)
	}
	if a.ManifestKeysPath != "" {
		if _, err := os.Stat(a.ManifestKeysPath); err != nil {
			fmt.Fprintf(w, "  ✗ Agent.ManifestKeysPath: %v\n", err)
			return err
		}
		fmt.Fprintf(w, "  ✓ Agent.ManifestKeysPath: %s\n", a.ManifestKeysPath)
	}
	if a.DesiredPath != "" {
		if _, err := os.Stat(a.DesiredPath); err != nil {
			fmt.Fprintf(w, "  ! Agent.DesiredPath 不存在（启动时不会应用）: %v\n", err)
		} else {
			fmt.Fprintf(w, "  ✓ Agent.DesiredPath: %s\n", a.DesiredPath)
		}
	}
	if err := checkAgentPanel(w, a.Panel); err != nil {
		return err
	}
	if online {
		return checkAgentManifestOnline(w, a)
	}
	return nil
}

// checkAgentManifestOnline fetches the manifest the panel serves and reports
// its sequence. It prints no document content and the token never appears in
// the URL or the output. The signature is not checked here: the agent verifies
// it locally before using the manifest, and "check" only reports what the panel
// currently serves.
func checkAgentManifestOnline(w io.Writer, a *AgentConfig) error {
	pc := a.Panel
	if pc == nil || !pc.Enabled || !pc.ManifestSyncEnabled() {
		return nil
	}
	token, err := pc.ResolveToken()
	if err != nil {
		fmt.Fprintf(w, "  ✗ %v\n", err)
		return err
	}
	c, err := panelclient.New(panelclient.Options{
		BaseURL:           pc.URL,
		MachineID:         pc.MachineID,
		Token:             token,
		AllowInsecureHTTP: pc.AllowInsecureHTTP,
	})
	if err != nil {
		fmt.Fprintf(w, "  ✗ 内核清单: %v\n", err)
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := c.Manifest(ctx, panelclient.ManifestRequest{})
	switch {
	case errors.Is(err, panelclient.ErrNoManifest):
		fmt.Fprintln(w, "  内核清单: 面板尚未发布（HTTP 404 no_manifest）")
		return nil
	case err != nil:
		fmt.Fprintf(w, "  ✗ 内核清单拉取失败: %v\n", err)
		return err
	case res.NotModified:
		fmt.Fprintln(w, "  内核清单: 未修改（HTTP 304）")
		return nil
	}
	var env struct {
		Sequence int64 `json:"sequence"`
	}
	if err := json.Unmarshal(res.Raw, &env); err != nil {
		fmt.Fprintf(w, "  ✗ 内核清单不是合法 JSON: %v\n", err)
		return err
	}
	fmt.Fprintf(w, "  ✓ 内核清单: sequence %d（%d 字节；本机验签通过后才会启用）\n", env.Sequence, len(res.Raw))
	return nil
}

// checkAgentPanel reports the panel link section. It never connects: it
// validates the settings and reads the token file (so a bad file mode is found
// before the service starts). The token itself is never printed.
func checkAgentPanel(w io.Writer, pc *AgentPanelConfig) error {
	if pc == nil || !pc.Enabled {
		return nil
	}
	// Structure and URL were validated by LoadConfig.
	pull, report := pc.Intervals()
	fmt.Fprintf(w, "  Agent.Panel: 已启用（%s，机器 ID %d，拉取间隔 %s，上报间隔 %s）\n", pc.URL, pc.MachineID, pull, report)
	if (pc.PullIntervalSec != 0 && time.Duration(pc.PullIntervalSec)*time.Second != pull) ||
		(pc.ReportIntervalSec != 0 && time.Duration(pc.ReportIntervalSec)*time.Second != report) {
		fmt.Fprintln(w, "  ! 间隔已被限制在 10–300 秒之内")
	}
	if pc.ManifestSyncEnabled() {
		every := pc.ManifestInterval()
		fmt.Fprintf(w, "  内核清单同步: 已启用（间隔 %s；面板下发、本机验签）\n", every)
		if pc.ManifestIntervalSec != 0 && time.Duration(pc.ManifestIntervalSec)*time.Second != every {
			fmt.Fprintln(w, "  ! 内核清单间隔已被限制在 300–86400 秒之内")
		}
	} else {
		fmt.Fprintln(w, "  内核清单同步: 已关闭（Agent.Panel.ManifestSync=false）")
	}
	if pc.AllowInsecureHTTP {
		fmt.Fprintln(w, "  ! Agent.Panel.AllowInsecureHTTP 已开启：令牌将以明文传输，仅限开发环境")
	}
	if _, err := pc.ResolveToken(); err != nil {
		fmt.Fprintf(w, "  ✗ %v\n", err)
		return err
	}
	if pc.TokenFile != "" {
		fmt.Fprintf(w, "  ✓ Agent.Panel.TokenFile: %s\n", pc.TokenFile)
	} else {
		fmt.Fprintln(w, "  ! 令牌写在配置文件里；建议改用 Agent.Panel.TokenFile（权限 600）")
	}
	return nil
}

// checkMachineNodes reports the machine-mode node list. Offline it only states
// where the nodes come from; online it asks the panel for the list. The token
// is never printed, and neither is anything from NodeControllers: only the
// overridden node ids are named.
func checkMachineNodes(w io.Writer, pc *AgentPanelConfig, online bool) error {
	token, err := pc.ResolveToken()
	if err != nil {
		fmt.Fprintf(w, "  ✗ %v\n", err)
		return err
	}
	if ids := pc.NodeControllerIDs(); len(ids) > 0 {
		fmt.Fprintf(w, "  本地覆盖: 节点 %s（共 %d 个；配置与凭据只在本机使用，不会下发到面板）\n", pc.NodeControllerIDList(), len(ids))
	}
	if !online {
		fmt.Fprintf(w, "  机器模式: 节点由面板下发（机器 ID %d；加 --online 可列出节点）\n", pc.MachineID)
		return nil
	}
	c := xboard.New(xboard.Config{APIHost: pc.URL, MachineID: pc.MachineID, MachineToken: token})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	list, version, err := c.ListMachineNodes(ctx)
	if err != nil {
		fmt.Fprintf(w, "  ✗ 机器节点列表（机器 ID %d）: %v\n", pc.MachineID, err)
		return err
	}
	fmt.Fprintf(w, "  ✓ 机器节点列表（机器 ID %d）: %d 个节点，版本 %s\n", pc.MachineID, len(list), version)
	for _, mn := range list {
		fmt.Fprintf(w, "      - 节点 %d: %s %s\n", mn.ID, mn.Type, mn.Name)
	}
	if len(list) == 0 {
		fmt.Fprintln(w, "  ! 面板当前没有给这台机器分配节点")
	}
	return nil
}

// quietKernelLog drops kernel messages below warning. Building configs before
// an instance exists logs through Xray's default handler, which does not
// filter by level (e.g. router debug lines).
func quietKernelLog() {
	xlog.RegisterHandler(warningFilter{next: xlog.NewLogger(xlog.CreateStdoutLogWriter())})
}

type warningFilter struct{ next xlog.Handler }

func (f warningFilter) Handle(msg xlog.Message) {
	if gm, ok := msg.(*xlog.GeneralMessage); ok && gm.Severity > xlog.Severity_Warning {
		return
	}
	f.next.Handle(msg)
}

// reportLegacyTags lists XrayR-style inbound tags (V2ray_0.0.0.0_65534) in
// route.json. They keep working: W1nCray maps them to the node listening on
// that port; the report says which node, and recommends the new tag.
func reportLegacyTags(w io.Writer, cfg *Config, nodePorts map[int]string, online bool) {
	refs, err := core.LegacyTagsInRoute(cfg.RouteConfigPath, cfg.InboundConfigPath)
	if err != nil || len(refs) == 0 {
		return
	}
	for _, r := range refs {
		switch node, ok := nodePorts[r.Port]; {
		case ok:
			fmt.Fprintf(w, "  ! route.json 使用了 XrayR 旧入站 tag %s，已自动对应到 %s（建议改为新 tag）\n", r.Tag, node)
		case online:
			fmt.Fprintf(w, "  ! route.json 使用了 XrayR 旧入站 tag %s，但没有节点监听端口 %d，该规则不会生效\n", r.Tag, r.Port)
		default:
			fmt.Fprintf(w, "  ! route.json 使用了 XrayR 旧入站 tag %s（对应端口 %d 的节点；加 --online 可查看对应关系）\n", r.Tag, r.Port)
		}
	}
}
