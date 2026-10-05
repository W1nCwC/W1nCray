package panel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	xlog "github.com/xtls/xray-core/common/log"

	"github.com/W1nCwC/W1nCray/common/cert"
	"github.com/W1nCwC/W1nCray/core"
	"github.com/W1nCwC/W1nCray/node"
)

// Check validates a config file without serving traffic. Offline it checks
// the config and every referenced JSON file with the Xray kernel; online it
// also fetches each node from the panel and builds its inbound and rules.
func Check(path string, online bool, w io.Writer) error {
	cfg, err := LoadConfig(path)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "配置文件: %s（%d 个节点）\n", path, len(cfg.NodesConfig))
	failed := false
	if cfg.Agent != nil && cfg.Agent.Enabled {
		if err := checkAgent(w, cfg); err != nil {
			failed = true
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
				fmt.Fprintf(w, "  ✗ %s: %v\n", ctl.Tag(), err)
				continue
			}
			fmt.Fprintf(w, "  ✓ %s: %s\n", ctl.Tag(), summary)
			ns = append(ns, ctl.NameServers()...)
			if p := ctl.PendingPort(); p > 0 {
				if _, taken := nodePorts[p]; !taken {
					nodePorts[p] = ctl.Tag()
				}
			}
		}
	}

	reportLegacyTags(w, cfg, nodePorts, online)
	opts := coreOptions(cfg, ns)
	// Keep the kernel's debug/info output out of the check report.
	if opts.LogLevel == "debug" || opts.LogLevel == "info" {
		opts.LogLevel = "warning"
	}
	opts.AccessPath, opts.ErrorPath = "", ""
	if errs := core.CheckFiles(opts); len(errs) > 0 {
		failed = true
		for _, e := range errs {
			fmt.Fprintf(w, "  ✗ %v\n", e)
		}
	}
	if c, err := core.New(opts); err != nil {
		failed = true
		fmt.Fprintf(w, "  ✗ Xray 实例: %v\n", err)
	} else {
		c.Close()
		fmt.Fprintln(w, "  ✓ Xray 实例构建成功（dns/route/自定义出入站）")
	}
	if failed {
		return errors.New("检查未通过")
	}
	fmt.Fprintln(w, "检查通过")
	return nil
}

// checkAgent reports the agent section and verifies the files it references.
// A missing manifest is not fatal (only the builtin xray engine runs then),
// but a configured path that does not exist is.
func checkAgent(w io.Writer, cfg *Config) error {
	a := cfg.Agent
	fmt.Fprintf(w, "  Agent: 已启用（状态目录 %s，内核目录 %s）\n", a.StateDir, a.KernelsDir)
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
