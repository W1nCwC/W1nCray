package agentd

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

	"github.com/W1nCwC/W1nCray/agent/agentcfg"
	"github.com/W1nCwC/W1nCray/agent/panelclient"
	"github.com/W1nCwC/W1nCray/config"
)

// Check validates the agent part of a config file without serving traffic. It
// never looks at the Xray section: `W1nCray-xray check` checks the kernel side.
func Check(path string, online bool, w io.Writer) error {
	_, err := CheckReport(path, online, w)
	return err
}

// CheckReport runs exactly the same validation as Check and also returns the
// individual failure items (the lines starting with "✗").
func CheckReport(path string, online bool, w io.Writer) ([]string, error) {
	rec := &failureRecorder{w: w}
	// agent.yml is reported first: it takes part in the load, so a broken one
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
	fmt.Fprintf(rec, "配置文件: %s\n", path)
	if cfg.Agent == nil || !cfg.Agent.Enabled {
		fmt.Fprintln(rec, "  Agent: 未启用（本机只运行 Xray 内核；用 W1nCray-xray check 检查内核配置）")
		fmt.Fprintln(rec, "检查通过")
		return nil, nil
	}
	if err := checkAgent(rec, cfg, online); err != nil {
		return rec.items(), errors.New("检查未通过")
	}
	fmt.Fprintln(rec, "检查通过")
	return nil, nil
}

// failureRecorder forwards everything to the wrapped writer and records the
// lines Check marks as failures ("  ✗ …").
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

func (r *failureRecorder) record(line string) {
	s := strings.TrimSpace(line)
	if strings.HasPrefix(s, "✗") {
		r.got = append(r.got, s)
	}
}

func (r *failureRecorder) items() []string {
	if len(r.rest) > 0 {
		r.record(string(r.rest))
		r.rest = nil
	}
	return r.got
}

// checkAgentYML reports agent.yml before anything else. The file is part of
// the load, so a broken one stops the service from starting: its parse error
// belongs on the first screen, and the operator must also be able to see that
// it is the file in charge (design R5, ruling 1). It prints nothing for the old
// single-file layout.
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
	// A config.yml that does not load is reported below, so the hint is simply
	// skipped here.
	if other, err := config.ConfigBlockAgent(configPath); err == nil && other != nil {
		fmt.Fprintf(w, "  ! %s 的 Agent 段被 agent.yml 覆盖（已忽略）\n", configPath)
	}
	fmt.Fprintf(w, "  ✓ agent.yml 已解析（生效来源 %s）\n", path)
	return nil
}

// checkAgent reports the agent section and verifies the files it references.
// A missing manifest is not fatal (only external kernels can be installed
// then), but a configured path that does not exist is.
func checkAgent(w io.Writer, cfg *Config, online bool) error {
	a := cfg.Agent
	source := cfg.AgentSourcePath()
	if source == "" {
		source = "未知"
	}
	fmt.Fprintf(w, "  Agent: 已启用（来源 %s，状态目录 %s，内核目录 %s）\n", source, a.StateDir, a.KernelsDir)
	if a.ManifestPath == "" {
		fmt.Fprintln(w, "  ! Agent.ManifestPath 未设置：外部内核无法安装（Xray 内核由 W1nCray-xray 提供）")
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
	if a.KernelsAllowHTTP() {
		fmt.Fprintln(w, "  ! Agent.Kernels.AllowHTTP 已开启：内核资产允许明文 http:// 镜像（签名与 sha256 校验照旧）")
	} else {
		fmt.Fprintln(w, "  内核源: 仅 https（Agent.Kernels.AllowHTTP=false）")
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
	// Structure and URL were validated by the loader.
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
