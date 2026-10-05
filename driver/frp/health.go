package frp

import (
	"context"
	"net"
	"strconv"

	"github.com/W1nCwC/W1nCray/agent/driver"
)

// probeHost maps a bind address to one that can be used locally.
func probeHost(addr string) string {
	switch addr {
	case "", "0.0.0.0":
		return "127.0.0.1"
	case "::":
		return "::1"
	}
	return addr
}

// udpHeld reports whether somebody holds the UDP port of the claim. UDP
// cannot be dialled meaningfully, so a bind attempt is used: it fails exactly
// when the port is taken. It has no side effects on the service.
func udpHeld(c driver.PortClaim) bool {
	pc, err := net.ListenPacket("udp", net.JoinHostPort(probeHost(c.Addr), strconv.Itoa(c.Port)))
	if err != nil {
		return true
	}
	_ = pc.Close()
	return false
}

// controlUp reports the state of the control endpoint of a portal whose admin
// API answers: frps creates its control listener before it serves the admin
// API, so a TCP control port needs no probe (dialling it would only make frps
// log a failed TLS check). The UDP side of a kcp/quic control port is checked
// by a bind attempt.
func controlUp(u *unit) bool {
	for _, c := range controlClaims(u) {
		if c.Proto == "udp" && !udpHeld(c) {
			return false
		}
	}
	return true
}

// isControlClaim tells the claims of the control endpoint from the public ones.
func isControlClaim(u *unit, c driver.PortClaim) bool {
	return c.Port == u.ControlPort && c.Addr == u.ControlAddr
}

func controlClaims(u *unit) []driver.PortClaim {
	var out []driver.PortClaim
	for _, c := range u.Claims {
		if isControlClaim(u, c) {
			out = append(out, c)
		}
	}
	return out
}

// Health implements driver.Driver.
//
// Portal: Running = frps alive. Listening = the control endpoint is up and
// every public port is registered, which happens only once a bridge is
// connected, so Listening stays false until then. The public ports are not
// dialled: a connection there would be forwarded through the tunnel to the
// real service behind the bridge. frps binds a public port exactly while its
// proxy is online, so "online" in the frps API is the listening state.
// Targets maps "tcp:<port>" / "udp:<port>" to that state.
//
// Bridge: Running = frpc alive, Listening = every proxy is registered on the
// portal (phase "running"); Err carries the first problem (not connected, wrong
// token, port outside the portal's allowPorts, failed health check). Targets
// maps the local "host:port" to the registration state of its proxies; with a
// health check configured a failing target shows up as not running.
func (d *Driver) Health(ctx context.Context, rt driver.Runtime) driver.Health {
	cur := d.snapshotCurrent()
	h := driver.Health{Instances: map[string]driver.InstanceHealth{}}
	for _, id := range sortedKeys(cur) {
		u := cur[id]
		ih := driver.InstanceHealth{ConfigHash: u.Hash}
		if rt.Sup == nil {
			ih.Err = "no supervisor"
			h.Instances[id] = ih
			continue
		}
		st := rt.Sup.Status(procID(u))
		ih.Running = st.Running
		if !st.Running {
			ih.Err = "process not running"
			if st.LastExit != "" {
				ih.Err += ": " + st.LastExit
			}
			h.Instances[id] = ih
			continue
		}
		a, ok := d.adminFor(rt, id)
		if !ok {
			ih.Err = "admin endpoint unknown"
			h.Instances[id] = ih
			continue
		}
		if u.Role == rolePortal {
			d.portalHealth(ctx, a, u, &ih)
		} else {
			d.bridgeHealth(ctx, a, u, &ih)
		}
		h.Instances[id] = ih
	}
	return h
}

func (d *Driver) portalHealth(ctx context.Context, a adminInfo, u *unit, ih *driver.InstanceHealth) {
	listening := controlUp(u)
	online := map[string]bool{}
	ih.Targets = map[string]bool{}
	for _, typ := range []string{"tcp", "udp"} {
		ps, err := a.proxies(ctx, typ)
		if err != nil {
			ih.Err = err.Error()
			return
		}
		for _, p := range ps {
			key := typ + ":" + strconv.Itoa(p.Conf.RemotePort)
			up := p.Status == "online"
			ih.Targets[key] = up
			if up {
				online[key] = true
			}
		}
	}
	for _, c := range u.Claims {
		if !isControlClaim(u, c) && !online[c.Proto+":"+strconv.Itoa(c.Port)] {
			listening = false
		}
	}
	ih.Listening = listening
}

func (d *Driver) bridgeHealth(ctx context.Context, a adminInfo, u *unit, ih *driver.InstanceHealth) {
	ps, err := a.status(ctx)
	if err != nil {
		ih.Err = err.Error()
		return
	}
	byName := map[string]frpcProxyStatus{}
	for _, p := range ps {
		byName[p.Name] = p
	}
	ih.Targets = map[string]bool{}
	all := len(u.Proxies) > 0
	for _, m := range u.Proxies {
		p, ok := byName[m.Name]
		up := ok && p.Status == "running"
		if !up {
			all = false
			switch {
			case ih.Err != "":
			case !ok:
				// frpc lists no proxy before the control connection to the
				// portal is up (portal down, wrong token, certificate not
				// trusted, ...); the reason is in the frpc log.
				ih.Err = "not connected to the portal"
			case p.Err != "":
				ih.Err = p.Err
			case p.Status != "":
				ih.Err = "proxy " + m.Name + " is " + p.Status
			}
		}
		if prev, seen := ih.Targets[m.Local]; !seen || prev {
			ih.Targets[m.Local] = up
		}
	}
	ih.Listening = all
}
