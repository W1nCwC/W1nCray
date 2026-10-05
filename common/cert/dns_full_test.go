//go:build !dnslite && !nodnsproviders

package cert

import (
	"strings"
	"testing"
)

func TestFullBuildKeepsLegoRegistry(t *testing.T) {
	if BuildFlavor != "full" {
		t.Fatalf("flavor %q", BuildFlavor)
	}
	// An unknown provider is lego's own error, as before the build tags existed.
	if _, err := newDNSProvider("no-such-provider"); err == nil || !strings.Contains(err.Error(), "unrecognized DNS provider") {
		t.Fatalf("err = %v", err)
	}
	// Providers outside the lite set are linked in: lego either constructs
	// them (route53 uses the AWS default credential chain) or complains about
	// missing credentials, but never calls them unrecognized.
	for _, n := range []string{"route53", "alidns", "dnspod"} {
		if _, err := newDNSProvider(n); err != nil && strings.Contains(err.Error(), "unrecognized") {
			t.Errorf("%s should be known to the full build: %v", n, err)
		}
	}
	if !DNSProviderSupported("route53") || DNSProviderSupported("") {
		t.Fatal("DNSProviderSupported")
	}
}
