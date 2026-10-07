//go:build dnslite && !nodnsproviders

package cert

import (
	"fmt"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns/alidns"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/providers/dns/dnspod"
	"github.com/go-acme/lego/v4/providers/dns/godaddy"
	"github.com/go-acme/lego/v4/providers/dns/namesilo"
	"github.com/go-acme/lego/v4/providers/dns/tencentcloud"

	"github.com/W1nCwC/W1nCray/common/certcfg"
)

// BuildFlavor, see dns_full.go.
const BuildFlavor = certcfg.BuildFlavor

// liteProviders are named exactly like lego's registry
// (providers/dns/zz_gen_dns_providers.go) so configs stay valid.
var liteProviders = map[string]func() (challenge.Provider, error){
	"alidns": func() (challenge.Provider, error) {
		p, err := alidns.NewDNSProvider()
		if err != nil {
			return nil, err
		}
		return p, nil
	},
	"cloudflare": func() (challenge.Provider, error) {
		p, err := cloudflare.NewDNSProvider()
		if err != nil {
			return nil, err
		}
		return p, nil
	},
	"dnspod": func() (challenge.Provider, error) {
		p, err := dnspod.NewDNSProvider()
		if err != nil {
			return nil, err
		}
		return p, nil
	},
	"godaddy": func() (challenge.Provider, error) {
		p, err := godaddy.NewDNSProvider()
		if err != nil {
			return nil, err
		}
		return p, nil
	},
	"namesilo": func() (challenge.Provider, error) {
		p, err := namesilo.NewDNSProvider()
		if err != nil {
			return nil, err
		}
		return p, nil
	},
	"tencentcloud": func() (challenge.Provider, error) {
		p, err := tencentcloud.NewDNSProvider()
		if err != nil {
			return nil, err
		}
		return p, nil
	},
}

func newDNSProvider(name string) (challenge.Provider, error) {
	if f, ok := liteProviders[name]; ok {
		return f()
	}
	return nil, fmt.Errorf("DNS 供应商 %q 不在当前构建（lite 版，仅含 alidns / cloudflare / dnspod / godaddy / namesilo / tencentcloud）中；请安装完整版: W1nCray update --full", name)
}

// DNSProviderSupported reports whether DNS-01 can use the provider in this
// build.
func DNSProviderSupported(name string) bool { return certcfg.DNSProviderSupported(name) }
