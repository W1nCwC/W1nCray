package panel

import (
	"context"
	"errors"
	"fmt"
	"io"
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
