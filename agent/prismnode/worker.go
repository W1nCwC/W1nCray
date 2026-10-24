package prismnode

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"sync/atomic"
	"time"

	"github.com/W1nCwC/W1nCray/agent/prismapi"
	"github.com/W1nCwC/W1nCray/api/xboard"
)

// worker keeps the users and the traffic of one node in step with the panel.
type worker struct {
	id       int
	nodeType string
	tag      string
	cancel   context.CancelFunc

	// users is the last list the panel sent (the client answers an unchanged
	// list with ErrNotModified and keeps no copy).
	users []xboard.User

	// seen is the generation of the user tables the kernel was last sent;
	// a controller generation above it forces a fresh send.
	seen atomic.Uint64
}

// reconcile starts a worker for every node of the document that has none,
// stops the workers of nodes that are gone and restarts a worker whose kernel
// tag changed.
func (c *Controller) reconcile(ctx context.Context, nodes []xboard.PrismNode) {
	want := make(map[int]xboard.PrismNode, len(nodes))
	for _, n := range nodes {
		want[n.ID] = n
	}

	c.mu.Lock()
	if c.stopped || c.parent == nil {
		c.mu.Unlock()
		return
	}
	parent := c.parent
	var gone []*worker
	for id, w := range c.workers {
		n, ok := want[id]
		if !ok || n.Tag != w.tag || n.Type != w.nodeType {
			gone = append(gone, w)
			delete(c.workers, id)
		}
	}
	var start []xboard.PrismNode
	for _, n := range nodes {
		if _, ok := c.workers[n.ID]; !ok {
			start = append(start, n)
		}
	}
	sort.Slice(start, func(i, j int) bool { return start[i].ID < start[j].ID })
	for _, n := range start {
		wctx, cancel := context.WithCancel(parent)
		w := &worker{id: n.ID, nodeType: n.Type, tag: n.Tag, cancel: cancel}
		c.workers[n.ID] = w
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			c.runWorker(wctx, w)
		}()
	}
	c.mu.Unlock()

	for _, w := range gone {
		w.cancel()
	}
}

func (c *Controller) generationNow() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.generation
}

func (c *Controller) nextSeq() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.o.Now().UnixMilli()
	if now <= c.seq {
		now = c.seq + 1
	}
	c.seq = now
	return now
}

func (c *Controller) runWorker(ctx context.Context, w *worker) {
	api := c.o.Panel.Node(w.id, w.nodeType)
	pull, push := c.intervals(ctx, api)
	c.log.Infof("prismnode: 节点 %d（%s）开始同步，用户每 %s、流量每 %s", w.id, w.tag, pull, push)

	// The first round runs at once: the kernel serves nobody until it has users.
	c.pullUsers(ctx, w, api, true)
	pullT := time.NewTicker(pull)
	defer pullT.Stop()
	pushT := time.NewTicker(push)
	defer pushT.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-pullT.C:
			c.pullUsers(ctx, w, api, false)
		case <-pushT.C:
			c.push(ctx, w, api)
		}
	}
}

func (c *Controller) intervals(ctx context.Context, api NodeAPI) (pull, push time.Duration) {
	pull, push = c.o.DefaultInterval, c.o.DefaultInterval
	cfgCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	nc, err := api.GetNodeConfig(cfgCtx)
	if err != nil || nc == nil || nc.BaseConfig == nil {
		return pull, push
	}
	if v := time.Duration(nc.BaseConfig.PullInterval) * time.Second; v >= c.o.MinInterval {
		pull = v
	}
	if v := time.Duration(nc.BaseConfig.PushInterval) * time.Second; v >= c.o.MinInterval {
		push = v
	}
	return pull, push
}

// pullUsers fetches the node's users and replaces the kernel's user table. An
// unchanged list (the client answers it with the cached copy) is still sent
// when the kernel restarted since.
func (c *Controller) pullUsers(ctx context.Context, w *worker, api NodeAPI, first bool) {
	rctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	users, err := api.GetUsers(rctx)
	gen := c.generationNow()
	switch {
	case errors.Is(err, xboard.ErrNotModified):
		// Unchanged. A restarted kernel (a newer generation) needs the table
		// again, so the copy kept here is sent.
		if w.users == nil || (w.seen.Load() >= gen && !first) {
			return
		}
		users = w.users
	case err != nil:
		c.log.Warnf("prismnode: 节点 %d 拉取用户失败: %v", w.id, err)
		return
	default:
		w.users = users
	}
	out := make([]prismapi.User, 0, len(users))
	for _, u := range users {
		if int(u.ID) <= 0 || string(u.UUID) == "" {
			continue
		}
		speed := int64(0)
		if u.SpeedLimit > 0 {
			speed = int64(u.SpeedLimit) * 1_000_000 / 8
		}
		out = append(out, prismapi.User{ID: int(u.ID), UUID: string(u.UUID), SpeedBps: speed, DeviceLimit: int(u.DeviceLimit)})
	}
	res, serr := c.o.Kernel.SetUsers(rctx, w.tag, c.nextSeq(), out)
	if serr != nil {
		var pe *prismapi.Error
		if errors.As(serr, &pe) && pe.IsNotFound() {
			// The kernel has no such inbound yet (it is being rebuilt): the
			// next round sends the table again.
			return
		}
		c.log.Warnf("prismnode: 节点 %d 写入用户失败: %v", w.id, serr)
		return
	}
	w.seen.Store(gen)
	if res.Added > 0 || res.Removed > 0 {
		c.log.Infof("prismnode: 节点 %d 用户 +%d -%d（踢出 %d 条连接）", w.id, res.Added, res.Removed, res.Kicked)
	}
}

// push reports the traffic and the online devices, refreshes the panel-wide
// device counts and reports the machine load. Traffic is committed in the
// kernel only after the panel accepted it, so nothing is lost on a failure.
func (c *Controller) push(ctx context.Context, w *worker, api NodeAPI) {
	rctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	stats, err := c.o.Kernel.Stats(rctx, w.tag)
	if err != nil {
		c.log.Debugf("prismnode: 节点 %d 读取统计失败: %v", w.id, err)
		return
	}
	if len(stats.Traffic) > 0 {
		traffic := make(map[int][2]int64, len(stats.Traffic))
		for _, t := range stats.Traffic {
			cur := traffic[t.ID]
			traffic[t.ID] = [2]int64{cur[0] + t.Up, cur[1] + t.Down}
		}
		if perr := api.PushTraffic(rctx, traffic); perr != nil {
			c.log.Errorf("prismnode: 节点 %d 上报流量失败: %v", w.id, perr)
			return
		}
		if cerr := c.o.Kernel.Commit(rctx, w.tag, stats.Snapshot, stats.BootID); cerr != nil {
			var pe *prismapi.Error
			if errors.As(cerr, &pe) && pe.IsStale() {
				c.log.Warnf("prismnode: 节点 %d 流量快照已失效（内核重启？），本轮已上报的流量不会再扣减", w.id)
			} else {
				c.log.Warnf("prismnode: 节点 %d 提交流量快照失败: %v", w.id, cerr)
			}
		}
	}
	alive := make(map[int][]string, len(stats.Alive))
	for _, a := range stats.Alive {
		alive[a.ID] = a.IPs
	}
	if len(alive) > 0 {
		if aerr := api.PushAlive(rctx, alive); aerr != nil {
			c.log.Debugf("prismnode: 节点 %d 上报在线设备失败: %v", w.id, aerr)
		}
	}
	if counts, gerr := api.GetAliveList(rctx); gerr == nil {
		_ = c.o.Kernel.SetDevices(rctx, w.tag, counts)
	} else {
		var se *xboard.StatusError
		if !errors.As(gerr, &se) || (se.Code != http.StatusNotFound && se.Code != http.StatusMethodNotAllowed) {
			c.log.Debugf("prismnode: 节点 %d 读取在线设备失败: %v", w.id, gerr)
		}
	}
	if c.o.Sample != nil {
		if s, serr := c.o.Sample(); serr == nil && s != nil {
			if perr := api.PushStatus(rctx, s); perr != nil {
				c.log.Debugf("prismnode: 节点 %d 上报状态失败: %v", w.id, perr)
			}
		}
	}
}
