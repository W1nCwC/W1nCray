//go:build !dnslite && !nodnsproviders

package cert

import (
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns"
)

// BuildFlavor names the DNS-01 support compiled into this binary: "full" has
// every lego DNS provider, "lite" a handful of common ones and "none" none
// (the registry of all providers is more than half of the binary size).
const BuildFlavor = "full"

func newDNSProvider(name string) (challenge.Provider, error) {
	return dns.NewDNSChallengeProviderByName(name)
}

// DNSProviderSupported reports whether DNS-01 can use the provider in this
// build. The full build knows lego's whole registry: an unknown name is
// reported by lego when the certificate is requested.
func DNSProviderSupported(name string) bool { return name != "" }
