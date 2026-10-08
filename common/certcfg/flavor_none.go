//go:build nodnsproviders

package certcfg

// BuildFlavor, see flavor_full.go.
const BuildFlavor = "none"

// DNSProviderSupported is always false in this build.
func DNSProviderSupported(string) bool { return false }

// DNSProviderNames returns no providers in this build.
func DNSProviderNames() []string { return nil }
