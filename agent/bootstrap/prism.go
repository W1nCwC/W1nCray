package bootstrap

import (
	"context"
	"sync"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/prismapi"
	"github.com/W1nCwC/W1nCray/agent/prismnode"
	"github.com/W1nCwC/W1nCray/agent/prismsvc"
	"github.com/W1nCwC/W1nCray/agent/wsproto"
	"github.com/W1nCwC/W1nCray/api/xboard"
	"github.com/W1nCwC/W1nCray/common/serverstatus"
)

// prismPanel adapts the machine-mode panel client to prismnode.Panel. The
// agent talks to the panel itself (HTTPS with the machine token), it does not
// go through its own node relay.
type prismPanel struct {
	url       string
	machineID int
	token     string
	client    *xboard.Client
}

func newPrismPanel(url string, machineID int, token string) *prismPanel {
	return &prismPanel{
		url: url, machineID: machineID, token: token,
		client: xboard.New(xboard.Config{APIHost: url, MachineID: machineID, MachineToken: token}),
	}
}

func (p *prismPanel) Prism(ctx context.Context, etag string) (*xboard.Prism, error) {
	return p.client.GetMachinePrism(ctx, etag)
}

func (p *prismPanel) Node(id int, nodeType string) prismnode.NodeAPI {
	return xboard.New(xboard.Config{
		APIHost: p.url, MachineID: p.machineID, MachineToken: p.token,
		NodeID: id, NodeType: nodeType,
	})
}

// startPrism builds the Prism kernel controller of this machine and starts it
// (handoff 69). The capability prism_nodes is declared only when the machine
// has an init system the service manager supports: the panel then keeps Prism
// nodes out of the xray inventory, which would otherwise try to serve them.
// It returns a stop function that waits for the controller to end.
func (r *Runtime) startPrism(ctx context.Context, o RemoteOptions, log driver.Logger) func() {
	if r == nil || r.Kernels == nil || !o.AgentConfig.MachineNodesEnabled() {
		return func() {}
	}
	kernel, err := prismapi.New("unix:" + prismsvc.SocketPath())
	if err != nil {
		log.Warnf("bootstrap: Prism kernel unavailable: %v", err)
		return func() {}
	}
	popts := prismsvc.Options{
		Kernels:  r.Kernels,
		StateDir: r.stateDir,
		Status:   kernel.Status,
		Log:      log,
	}
	if r.Sup != nil { // a nil *Supervisor must not become a non-nil interface
		popts.Sup = r.Sup
		sup := r.Sup
		popts.RecoverOrphan = func(ctx context.Context, id string) error {
			_, err := sup.RecoverOrphan(ctx, id)
			return err
		}
	}
	mgr, err := prismsvc.New(popts)
	if err != nil {
		log.Warnf("bootstrap: Prism service management unavailable: %v", err)
		return func() {}
	}
	if mgr.Backend() == "" {
		log.Infof("bootstrap: Prism nodes are not supported on this machine's init system (procd without the agent supervisor); the capability is not declared")
		return func() {}
	}
	ctrl, err := prismnode.New(prismnode.Options{
		Panel:   newPrismPanel(o.URL, o.MachineID, o.Token),
		Kernel:  kernel,
		Service: mgr,
		Log:     log,
		Sample: func() (*xboard.Status, error) {
			s, err := serverstatus.Get()
			if err != nil {
				return nil, err
			}
			return &xboard.Status{
				CPU:  s.CPU,
				Mem:  xboard.Resource{Total: s.MemTotal, Used: s.MemUsed},
				Swap: xboard.Resource{Total: s.SwapTotal, Used: s.SwapUsed},
				Disk: xboard.Resource{Total: s.DiskTotal, Used: s.DiskUsed},
			}, nil
		},
	})
	if err != nil {
		log.Warnf("bootstrap: Prism controller unavailable: %v", err)
		return func() {}
	}
	r.Prism, r.PrismManager = ctrl, mgr
	r.prismOn.Store(true)

	pctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ctrl.Run(pctx)
	}()
	var once sync.Once

	return func() {
		once.Do(func() {
			r.prismOn.Store(false)
			cancel()
			<-done
		})
	}
}

// hintPrism asks the Prism controller to re-fetch its document now (the panel
// pushed a nodes hint). It is a no-op without a controller.
func (r *Runtime) hintPrism() {
	if r != nil && r.Prism != nil {
		r.Prism.Hint()
	}
}

// prismComponent is the components entry of the Prism kernel; nil when this
// machine runs none of it (the controller is absent or never saw a node).
func (r *Runtime) prismComponent() *wsproto.Component {
	if r == nil || r.Prism == nil || r.PrismManager == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	svc := r.PrismManager.Status(ctx)
	st := r.Prism.Status()
	if svc.State == prismsvc.StateNotInstalled && st.Nodes == 0 && st.Error == "" {
		return nil // nothing was ever asked of it
	}
	state := wsproto.StateStopped
	switch svc.State {
	case prismsvc.StateRunning:
		state = wsproto.StateRunning
	case prismsvc.StateFailed:
		state = wsproto.StateFailed
	case prismsvc.StateNotInstalled:
		state = "not_installed"
	}
	comp := wsproto.Component{
		Name:           prismapi.KernelName,
		Kind:           "kernel",
		Version:        svc.Version,
		State:          state,
		Instances:      []wsproto.ComponentInstance{},
		Runtime:        "panel",
		RuntimeVersion: st.Version,
		RuntimeError:   truncateUTF8(st.Error, maxRuntimeErrorBytes),
	}
	if st.Reachable {
		for _, in := range st.Kernel.Inbounds {
			comp.Instances = append(comp.Instances, wsproto.ComponentInstance{ID: in.Tag, State: wsproto.StateRunning, Conns: in.Conns})
		}
		if st.Kernel.StartedAt > 0 {
			if up := time.Now().Unix() - st.Kernel.StartedAt; up > 0 {
				comp.UptimeS = up
			}
		}
		comp.LastError = st.Kernel.LastError
	}

	return &comp
}
