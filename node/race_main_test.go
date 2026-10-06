//go:build race

package node

import (
	"fmt"
	"os"
	"testing"
)

// TestMain skips the whole package under -race: the e2e exercises REALITY
// (xtls/reality trips Go's checkptr: "pointer arithmetic result points to
// invalid allocation", reality conn.go:875) and the splithttp client and TLS
// certificate loader, which have data races inside upstream xray-core
// v1.260327.0 (client.go:179/189, config.go:253/90). Every reported frame in
// the -race logs is upstream; the package is fully exercised without -race.
func TestMain(m *testing.M) {
	if os.Getenv("W1NCRAY_FORCE_RACE_TESTS") == "" {
		fmt.Println("node: skipped under -race (upstream xtls/reality checkptr + splithttp/tls data races; see race_main_test.go)")
		os.Exit(0)
	}
	os.Exit(m.Run())
}
