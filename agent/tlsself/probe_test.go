package tlsself

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
)

// TestDerivedCertificateIsItsOwnCA proves the property the drivers rely on: a
// client that trusts the derived certificate (as its own CA) and sends the
// certificate's name as ServerName completes a handshake with a server that
// presents it. That is why gost can render `secure: true` + `caFile` pointing
// at the same PEM, and why the xray pin path works against a self-signed leaf.
func TestDerivedCertificateIsItsOwnCA(t *testing.T) {
	certPEM, keyPEM, _, err := SelfCert("probe-secret-0123456789abcdef", "tun.example.net")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(certPEM)) {
		t.Fatal("the derived certificate is not accepted into a pool")
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				sc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}})
				_ = sc.Handshake()
				_ = sc.Close()
			}()
		}
	}()
	conn, err := tls.Dial("tcp", l.Addr().String(), &tls.Config{
		RootCAs:    pool,
		ServerName: "tun.example.net",
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("a client trusting the derived certificate as its own CA failed: %v", err)
	}
	_ = conn.Close()
	// A wrong name must still fail: the name in the certificate is verified.
	if _, err := tls.Dial("tcp", l.Addr().String(), &tls.Config{
		RootCAs:    pool,
		ServerName: "other.example.net",
		MinVersion: tls.VersionTLS12,
	}); err == nil {
		t.Error("a mismatched serverName was accepted")
	}
}
