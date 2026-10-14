//go:build nodnsproviders

package cert

import (
	"fmt"

	"github.com/go-acme/lego/v4/challenge"

	"github.com/W1nCwC/W1nCray/common/certcfg"
)

// BuildFlavor, see dns_full.go.
const BuildFlavor = certcfg.BuildFlavor

func newDNSProvider(name string) (challenge.Provider, error) {
	return nil, fmt.Errorf("DNS-01 证书不在当前构建（none 版）中；请改用 http / tls / file 模式，或安装完整版: W1nCray update --full")
}

// DNSProviderSupported is always false in this build.
func DNSProviderSupported(name string) bool { return certcfg.DNSProviderSupported(name) }
