//go:build !dnslite && !nodnsproviders

package certcfg

import "slices"

// BuildFlavor names the DNS-01 support compiled into this binary: "full" has
// every lego DNS provider, "lite" a handful of common ones and "none" none
// (the registry of all providers is more than half of the binary size).
const BuildFlavor = "full"

// fullDNSProviders is the static name list of lego's DNS-01 registry. It is a
// copy of the generated switch in
// github.com/go-acme/lego/v4/providers/dns/zz_gen_dns_providers.go; the cert
// package (the only place that may link lego) asserts the two stay identical
// (common/cert/dns_registry_test.go). Keeping it here is what lets the agent
// answer "is this provider in this build?" without linking lego.
var fullDNSProviders = []string{
	"acme-dns", "acmedns", "active24", "alidns", "aliesa", "allinkl",
	"alwaysdata", "anexia", "artfiles", "arvancloud", "auroradns", "autodns",
	"axelname", "azion", "azure", "azuredns", "baiducloud", "beget",
	"binarylane", "bindman", "bluecat", "bluecatv2", "bookmyname", "brandit",
	"bunny", "checkdomain", "civo", "clouddns", "cloudflare", "cloudns",
	"cloudru", "cloudxns", "com35", "conoha", "conohav3", "constellix",
	"corenetworks", "cpanel", "czechia", "ddnss", "derak", "desec",
	"designate", "digitalocean", "directadmin", "dnsexit", "dnshomede", "dnsimple",
	"dnsmadeeasy", "dnspod", "dode", "domeneshop", "domainnameshop", "dreamhost",
	"duckdns", "dyn", "dyndnsfree", "dynu", "easydns", "edgecenter",
	"edgedns", "fastdns", "edgeone", "efficientip", "epik", "eurodns",
	"excedo", "exec", "exoscale", "f5xc", "freemyip", "gandi",
	"gandiv5", "gcloud", "gcore", "gigahostno", "glesys", "godaddy",
	"googledomains", "gravity", "hetzner", "hostingde", "hostinger", "hostingnl",
	"hosttech", "httpnet", "httpreq", "huaweicloud", "hurricane", "hyperone",
	"ibmcloud", "iij", "iijdpf", "infoblox", "infomaniak", "internetbs",
	"inwx", "ionos", "ionoscloud", "ipv64", "ispconfig", "ispconfigddns",
	"iwantmyname", "jdcloud", "joker", "keyhelp", "leaseweb", "liara",
	"lightsail", "limacity", "linode", "linodev4", "liquidweb", "loopia",
	"luadns", "mailinabox", "manageengine", "manual", "metaname", "metaregistrar",
	"mijnhost", "mittwald", "myaddr", "mydnsjp", "mythicbeasts", "namecheap",
	"namedotcom", "namesilo", "namesurfer", "nearlyfreespeech", "neodigit", "netcup",
	"netlify", "netnod", "nicmanager", "nicru", "nifcloud", "njalla",
	"nodion", "ns1", "octenium", "onecloudru", "onlinenet", "oraclecloud",
	"otc", "ovh", "pdns", "plesk", "porkbun", "rackspace",
	"rainyun", "rcodezero", "regfish", "regru", "rfc2136", "dnsupdate",
	"rimuhosting", "route53", "safedns", "sakuracloud", "scaleway", "selectel",
	"selectelv2", "selfhostde", "servercow", "shellrent", "simply", "sonic",
	"spaceship", "stackpath", "syse", "technitium", "tencentcloud", "timewebcloud",
	"todaynic", "transip", "ucloud", "ultradns", "uniteddomains", "variomedia",
	"vegadns", "vercel", "versio", "vinyldns", "virtualname", "vkcloud",
	"volcengine", "vscale", "vultr", "webnames", "webnamesru", "webnamesca",
	"websupport", "wedos", "westcn", "yandex", "yandex360", "yandexcloud",
	"zoneedit", "zoneee", "zonomi",
}

// DNSProviderSupported reports whether DNS-01 can use the provider in this
// build.
func DNSProviderSupported(name string) bool { return slices.Contains(fullDNSProviders, name) }

// DNSProviderNames returns the providers this build supports, sorted as in the
// registry.
func DNSProviderNames() []string { return slices.Clone(fullDNSProviders) }
