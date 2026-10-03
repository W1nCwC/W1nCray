package panel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

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

	var ns []core.NameServer
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
		}
	}

	opts := coreOptions(cfg, ns)
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
