//go:build dnslite && !nodnsproviders

package cert

import (
	"strings"
	"testing"
)

func TestLiteBuildProviders(t *testing.T) {
	if BuildFlavor != "lite" {
		t.Fatalf("flavor %q", BuildFlavor)
	}
	for _, n := range []string{"alidns", "cloudflare", "dnspod", "godaddy", "namesilo", "tencentcloud"} {
		if !DNSProviderSupported(n) {
			t.Errorf("%s must be supported", n)
		}
	}
	for _, n := range []string{"route53", "gcloud", "", "Cloudflare"} {
		if DNSProviderSupported(n) {
			t.Errorf("%q must not be supported", n)
		}
	}

	// A supported provider is constructed from its environment, like lego does.
	t.Setenv("CLOUDFLARE_DNS_API_TOKEN", "token")
	if p, err := newDNSProvider("cloudflare"); err != nil || p == nil {
		t.Fatalf("cloudflare: %v", err)
	}
	// Missing credentials are lego's error, not "unsupported".
	if _, err := newDNSProvider("alidns"); err == nil || strings.Contains(err.Error(), "不在当前构建") {
		t.Fatalf("alidns without credentials: %v", err)
	}
	// An unsupported provider tells the user how to fix it.
	_, err := newDNSProvider("route53")
	if err == nil || !strings.Contains(err.Error(), "route53") || !strings.Contains(err.Error(), "W1nCray update --full") {
		t.Fatalf("unsupported provider error: %v", err)
	}
}
