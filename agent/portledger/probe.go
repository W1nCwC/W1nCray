package portledger

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Sentinel errors returned (wrapped) by Probe.
var (
	// ErrInUse means the address is already bound by some socket.
	ErrInUse = errors.New("address already in use")
	// ErrPermission means the bind was refused for lack of privileges (for
	// example a port below 1024 without CAP_NET_BIND_SERVICE). In that case
	// the probe cannot tell whether the port is free.
	ErrPermission = errors.New("permission denied")
)

// Probe really binds proto ("tcp" or "udp") addr:port and closes the socket
// immediately. nil means the address was free. ErrInUse and ErrPermission are
// wrapped so callers can use errors.Is; any other failure (for example an
// address that is not assigned to this host) is returned as is.
//
// Probing never connects to anything, so it has no side effects on forwarding
// targets, but it also cannot tell who owns a bound port.
func Probe(proto, addr string, port int) error {
	if port < 1 || port > MaxPort {
		return fmt.Errorf("port %d out of range", port)
	}
	var hostport string
	switch addr {
	case "", "*":
		hostport = ":" + strconv.Itoa(port)
	default:
		hostport = net.JoinHostPort(addr, strconv.Itoa(port))
	}
	var err error
	switch strings.ToLower(proto) {
	case "tcp":
		var l net.Listener
		l, err = net.Listen("tcp", hostport)
		if err == nil {
			_ = l.Close()
		}
	case "udp":
		var pc net.PacketConn
		pc, err = net.ListenPacket("udp", hostport)
		if err == nil {
			_ = pc.Close()
		}
	default:
		return fmt.Errorf("invalid protocol %q", proto)
	}
	if err == nil {
		return nil
	}
	switch {
	case isAddrInUse(err):
		return fmt.Errorf("%w: %v", ErrInUse, err)
	case isPermission(err):
		return fmt.Errorf("%w: %v", ErrPermission, err)
	}
	return err
}
