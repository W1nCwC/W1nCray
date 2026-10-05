package gost

import (
	"context"
	"net"
	"strconv"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
)

// Health implements driver.Driver. An instance is healthy when the process is
// supervised and running, the API reports every service of the instance as
// ready, and the committed artifact hash is the one gost was given. With
// Options.ProbeConnect every claimed TCP port is additionally probed with a
// real connection. Per-target liveness is not available: gost's passive
// failure markers are not exposed by its API, so InstanceHealth.Targets stays
// nil.
func (d *Driver) Health(ctx context.Context, rt driver.Runtime) driver.Health {
	d.rt.mu.Lock()
	defer d.rt.mu.Unlock()
	h := driver.Health{Instances: map[string]driver.InstanceHealth{}}
	if checkRuntime(rt) != nil {
		return h
	}
	st, err := loadApplied(rt.StateDir, appliedFile)
	if err != nil {
		return h
	}
	ps := rt.Sup.Status(procID)
	var snap map[string]svcInfo
	var apiErr error
	if ps.Running {
		var ep endpoint
		if ep, apiErr = loadEndpoint(rt.StateDir); apiErr == nil {
			snap, apiErr = newAPIClient(ep, d.opts.APITimeout).services(ctx)
		}
	}
	for _, id := range st.ids() {
		ai := st.Instances[id]
		ih := driver.InstanceHealth{}
		switch {
		case !ps.Running:
			ih.Err = "gost process is not running"
			if ps.LastExit != "" {
				ih.Err += " (last exit: " + ps.LastExit + ")"
			}
		case apiErr != nil:
			ih.Err = "gost api unreachable: " + apiErr.Error()
		default:
			ih.Running, ih.Listening = true, true
			for _, name := range ai.Fragment.serviceNames() {
				s, ok := snap[name]
				if !ok || s.Status == nil || s.Status.State != "ready" {
					ih.Running, ih.Listening = false, false
					if ih.Err == "" {
						if ok && s.Status != nil {
							ih.Err = "service " + name + " is " + s.Status.State + ": " + s.lastEvent()
						} else {
							ih.Err = "service " + name + " is not registered"
						}
					}
				}
			}
			if ih.Running {
				ih.ConfigHash = ai.Hash
				if d.opts.ProbeConnect {
					for _, c := range d.claimsOf(ai) {
						if c.Proto == "tcp" && !probeTCP(ctx, c.Addr, c.Port) {
							ih.Listening = false
							if ih.Err == "" {
								ih.Err = "port " + strconv.Itoa(c.Port) + " did not accept a connection"
							}
						}
					}
				}
			}
		}
		h.Instances[id] = ih
	}
	return h
}

// claimsOf recomputes the port claims of a committed instance from its
// fragment's listening services (portal public ports are bound by the bridge
// and are not probed).
func (d *Driver) claimsOf(ai appliedInstance) []driver.PortClaim {
	var out []driver.PortClaim
	for _, s := range ai.Fragment.Services {
		if s.Listener.Type != "tcp" && s.Listener.Type != "tls" && s.Listener.Type != "ws" &&
			s.Listener.Type != "wss" && s.Listener.Type != "grpc" {
			continue
		}
		host, port, err := net.SplitHostPort(s.Addr)
		if err != nil {
			continue
		}
		n, _ := strconv.Atoi(port)
		out = append(out, driver.PortClaim{Proto: "tcp", Addr: host, Port: n})
	}
	return out
}

func probeTCP(ctx context.Context, addr string, port int) bool {
	if ip := net.ParseIP(addr); ip == nil || ip.IsUnspecified() {
		if ip != nil && ip.To4() == nil {
			addr = "::1"
		} else {
			addr = "127.0.0.1"
		}
	}
	dctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	var dd net.Dialer
	c, err := dd.DialContext(dctx, "tcp", net.JoinHostPort(addr, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	c.Close()
	return true
}
