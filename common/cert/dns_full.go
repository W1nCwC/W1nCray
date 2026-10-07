//go:build !dnslite && !nodnsproviders

package cert

import (
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns"

	"github.com/W1nCwC/W1nCray/common/certcfg"
)

// BuildFlavor names the DNS-01 support compiled into this binary, see
// common/certcfg.
const BuildFlavor = certcfg.BuildFlavor

func newDNSProvider(name string) (challenge.Provider, error) {
	return dns.NewDNSChallengeProviderByName(name)
}

// DNSProviderSupported reports whether DNS-01 can use the provider in this
// build. The list is static (common/certcfg); dns_registry_test.go asserts it
// matches lego's registry exactly.
func DNSProviderSupported(name string) bool { return certcfg.DNSProviderSupported(name) }
