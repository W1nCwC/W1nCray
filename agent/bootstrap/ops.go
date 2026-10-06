// This file is the production side of the operations commands: the component
// restarter (component_restart) and the late-result sink long commands use to
// deliver their final answer.

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/panelclient"
	"github.com/W1nCwC/W1nCray/agent/supervisor"
	"github.com/W1nCwC/W1nCray/agent/ws"
	"github.com/W1nCwC/W1nCray/agent/wsproto"
)

// componentRestarter restarts the supervised processes of one kernel
// component. Only the supervisor's own children are reachable, so the agent
// itself (which is not supervised) can never be restarted this way.
type componentRestarter struct{ rt *Runtime }

func (c componentRestarter) Restart(ctx context.Context, name string) (int, error) {
	if c.rt == nil || c.rt.Sup == nil {
		return 0, errors.New("no process supervisor is wired")
	}
	ids := componentProcessIDs(c.rt.Sup, name)
	if len(ids) == 0 {
		return 0, fmt.Errorf("component %q is not running", name)
	}
	restarted := 0
	for _, id := range ids {
		if err := c.rt.Sup.Restart(ctx, id); err != nil {
			return restarted, fmt.Errorf("restarting %s: %w", id, err)
		}
		restarted++
	}
	return restarted, nil
}

// componentProcessIDs returns the supervisor ids that belong to component
// name. The drivers name their processes "gost/main", "realm/<instance>" and
// "frp/frps-<instance>", so the component name is the id prefix.
func componentProcessIDs(sup *supervisor.Supervisor, name string) []string {
	var out []string
	for _, id := range sup.IDs() {
		if id == name || strings.HasPrefix(id, name+"/") {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// lateResult delivers the final result of a long command (one that already
// answered "accepted"). It prefers the WebSocket while it is connected and
// falls back to the HTTP link; both channels answer the same command id, and
// the panel keeps the command pending until the final result arrives
// (docs/WS-PROTOCOL.md section 7 ruling 7).
//
// A delivery that fails releases the command id, so the panel's redelivery runs
// the command again instead of being swallowed by a slot nothing will fill.
type lateResult struct {
	runner *panelclient.Runner
	ws     *ws.Client // nil until the WebSocket channel exists
	log    driver.Logger
}

// deliverTimeout bounds the HTTP fallback: it must not block the command's
// worker forever when the panel is unreachable.
const deliverTimeout = 15 * time.Second

func (l *lateResult) Deliver(id, status string, data json.RawMessage) {
	if l.ws != nil && l.ws.Connected() {
		env, err := ws.Encode(wsproto.TypeCmdResult, id, wsproto.CmdResult{Status: status, Result: json.RawMessage(data)})
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), ws.CommandQueueTimeout)
			err = l.ws.SendWait(ctx, env, ws.CommandQueueTimeout)
			cancel()
			if err == nil {
				l.runner.MarkAnswered(id)
				return
			}
		}
		l.warnf("bootstrap: final %s result of command %q not delivered over the WebSocket: %v", status, id, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), deliverTimeout)
	defer cancel()
	if err := l.runner.DeliverResult(ctx, id, status, data); err != nil {
		l.warnf("bootstrap: final %s result of command %q not delivered over HTTP: %v", status, id, err)
	}
}

func (l *lateResult) warnf(format string, args ...any) {
	if l.log != nil {
		l.log.Warnf(format, args...)
	}
}
