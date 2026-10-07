//go:build dnslite && !nodnsproviders

package certcfg

import "slices"

// BuildFlavor, see flavor_full.go.
const BuildFlavor = "lite"

// liteDNSProviders are named exactly like lego's registry
// (providers/dns/zz_gen_dns_providers.go) so configs stay valid. The list is
// static so the agent can answer "is this provider in this build?" without
// linking lego; common/cert/dns_registry_test.go checks it against the registry
// and against the providers the lite build really imports.
var liteDNSProviders = []string{
	"alidns", "cloudflare", "dnspod", "godaddy", "namesilo", "tencentcloud",
}

// DNSProviderSupported reports whether DNS-01 can use the provider in this
// build.
func DNSProviderSupported(name string) bool { return slices.Contains(liteDNSProviders, name) }

// DNSProviderNames returns the providers this build supports.
func DNSProviderNames() []string { return slices.Clone(liteDNSProviders) }
