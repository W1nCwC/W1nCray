package realm

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
)

// The real bind probe, on real sockets: a held port is "in use", a free one
// is not, and probing never connects to (or disturbs) the holder.
func TestBindProbe(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var accepted atomic.Int64
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			c.Close()
		}
	}()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcpPort := l.Addr().(*net.TCPAddr).Port
	udpPort := pc.LocalAddr().(*net.UDPAddr).Port
	claim := func(proto string, port int) driver.PortClaim {
		return driver.PortClaim{Proto: proto, Addr: "127.0.0.1", Port: port}
	}
	for i := 0; i < 3; i++ {
		if !bindProbe(claim("tcp", tcpPort)) || !bindProbe(claim("udp", udpPort)) {
			t.Fatal("a held port was reported free")
		}
	}
	time.Sleep(50 * time.Millisecond)
	if accepted.Load() != 0 {
		t.Fatal("probing connected to the listener")
	}
	l.Close()
	pc.Close()
	if bindProbe(claim("tcp", tcpPort)) || bindProbe(claim("udp", udpPort)) {
		t.Fatal("a free port was reported in use")
	}
	if bindProbe(claim("sctp", 1)) {
		t.Fatal("unknown protocol")
	}
	// An address that cannot be bound here is "not served", not "in use".
	if bindProbe(driver.PortClaim{Proto: "tcp", Addr: "203.0.113.77", Port: 9}) {
		t.Fatal("unbindable address reported in use")
	}
}
