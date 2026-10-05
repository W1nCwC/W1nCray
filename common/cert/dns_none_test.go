//go:build nodnsproviders

package cert

import (
	"strings"
	"testing"
)

func TestNoneBuildHasNoDNS(t *testing.T) {
	if BuildFlavor != "none" || DNSProviderSupported("cloudflare") {
		t.Fatalf("flavor %q", BuildFlavor)
	}
	if _, err := newDNSProvider("cloudflare"); err == nil || !strings.Contains(err.Error(), "W1nCray update --full") {
		t.Fatalf("err = %v", err)
	}
}
