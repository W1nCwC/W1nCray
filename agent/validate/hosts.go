package validate

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// Resolver resolves a host name. *net.Resolver satisfies it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Metadata endpoints that are refused even when AllowPrivate is set (they sit
// inside address ranges that AllowPrivate would otherwise open).
var metadataAddrs = []netip.Addr{
	netip.MustParseAddr("169.254.169.254"), // AWS/GCP/Azure/OpenStack/DO (also link-local)
	netip.MustParseAddr("169.254.170.2"),   // ECS task metadata (also link-local)
	netip.MustParseAddr("100.100.100.200"), // Alibaba Cloud (CGNAT range)
	netip.MustParseAddr("168.63.129.16"),   // Azure wire server (public range)
	netip.MustParseAddr("192.0.0.192"),     // Oracle legacy
	netip.MustParseAddr("fd00:ec2::254"),   // AWS IPv6 (ULA range)
}

var (
	cgnat      = netip.MustParsePrefix("100.64.0.0/10")
	thisNet    = netip.MustParsePrefix("0.0.0.0/8")
	reservedV4 = netip.MustParsePrefix("240.0.0.0/4") // includes 255.255.255.255
	siteLocal6 = netip.MustParsePrefix("fec0::/10")
	nat64      = netip.MustParsePrefix("64:ff9b::/96")
	sixToFour  = netip.MustParsePrefix("2002::/16")
	v4Compat   = netip.MustParsePrefix("::/96")
)

// targetPolicy decides which destination IPs the agent will forward to.
type targetPolicy struct {
	allowPrivate bool
	deny         []netip.Prefix
}

// denyReason returns why a destination address is refused, or "" if it is
// acceptable. Loopback, link-local, unspecified, multicast and metadata
// addresses are always refused; private and CGNAT space only when the local
// policy has not set allow_private; policy.deny_cidrs are always applied.
func (tp targetPolicy) denyReason(a netip.Addr) string {
	a = a.WithZone("").Unmap()
	switch {
	case a.IsUnspecified():
		return "unspecified address"
	case a.IsLoopback():
		return "loopback address"
	case a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast(), a.IsInterfaceLocalMulticast():
		return "link-local address"
	case a.IsMulticast():
		return "multicast address"
	}
	for _, m := range metadataAddrs {
		if a == m {
			return "cloud metadata address"
		}
	}
	if a.Is4() {
		if thisNet.Contains(a) {
			return "\"this network\" address (0.0.0.0/8)"
		}
		if reservedV4.Contains(a) {
			return "reserved/broadcast address"
		}
	}
	for _, p := range tp.deny {
		if p.Contains(a) {
			return "denied by policy.deny_cidrs (" + p.String() + ")"
		}
	}
	// IPv6 forms that embed an IPv4 address: judge the embedded address.
	if a.Is6() {
		b := a.As16()
		var emb netip.Addr
		switch {
		case nat64.Contains(a), v4Compat.Contains(a):
			emb = netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
		case sixToFour.Contains(a):
			emb = netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]})
		}
		if emb.IsValid() {
			if r := tp.denyReason(emb); r != "" {
				return "embeds an IPv4 address that is refused (" + r + ")"
			}
		}
	}
	if !tp.allowPrivate {
		switch {
		case a.IsPrivate(), siteLocal6.Contains(a):
			return "private address (policy.allow_private is off)"
		case cgnat.Contains(a):
			return "carrier-grade NAT address (policy.allow_private is off)"
		}
	}
	return ""
}

// isPrivateOrLocal is used for the accept_proxy_protocol listener rule.
func isPrivateOrLocal(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || siteLocal6.Contains(a)
}

// checkHostSyntax validates a destination host string and classifies it. A
// literal IP is returned as addr with ok=true; a name is returned with
// isName=true. Anything else gets a message.
//
// Names must be plain ASCII (use punycode for IDNs), made of LDH labels, and
// the last label must start with a letter. The last rule rejects the numeric
// shorthands that some resolvers expand to an IP ("127.1", "2130706433",
// "0x7f.1"), which Go's parser does not treat as an IP but getaddrinfo-based
// kernels do. "localhost" and "*.localhost" are refused outright.
func checkHostSyntax(host string) (addr netip.Addr, isName bool, msg string) {
	if host == "" {
		return netip.Addr{}, false, "must not be empty"
	}
	if len(host) > 253 {
		return netip.Addr{}, false, "too long"
	}
	for _, r := range host {
		if r > 0x7e || r < 0x21 {
			return netip.Addr{}, false, "contains whitespace, control or non-ASCII characters"
		}
	}
	if strings.ContainsAny(host, ":") {
		a, err := netip.ParseAddr(host)
		if err != nil {
			return netip.Addr{}, false, "not a valid IPv6 address (brackets, ports and zones are not allowed)"
		}
		if a.Zone() != "" {
			return netip.Addr{}, false, "IPv6 zones are not allowed"
		}
		return a, false, ""
	}
	if a, err := netip.ParseAddr(host); err == nil {
		return a, false, ""
	}
	labels := strings.Split(host, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 {
			return netip.Addr{}, false, "invalid host name (empty or over-long label)"
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return netip.Addr{}, false, "invalid host name (label starts or ends with '-')"
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return netip.Addr{}, false, fmt.Sprintf("invalid character %q in host name", c)
			}
		}
	}
	last := labels[len(labels)-1]
	if c := last[0]; !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
		return netip.Addr{}, false, "not an IP address and not a valid host name (last label must start with a letter)"
	}
	lh := strings.ToLower(host)
	if lh == "localhost" || strings.HasSuffix(lh, ".localhost") {
		return netip.Addr{}, false, "refers to the local host"
	}
	return netip.Addr{}, true, ""
}

// dnsRef remembers where a host name was used so a resolution failure can be
// attributed to the right field.
type dnsRef struct {
	index    int
	instance string
	field    string
}

const (
	defaultResolveTimeout = 3 * time.Second
	resolveConcurrency    = 8
)

// resolveAll resolves every collected host name and returns the errors.
//
// Policy for failures: a name that cannot be resolved is rejected at
// validation time, because the target policy cannot be checked for it. This is
// fail-closed on purpose. Resolution happens once, here; the kernel resolves
// again when it connects, so a name that points at a public address now and at
// a private one later (DNS rebinding) is not caught: the check is a
// TOCTOU-limited first line of defence, not a guarantee. Prefer literal IP
// targets for sensitive deployments.
func (v *validator) resolveAll() {
	if len(v.dns) == 0 {
		return
	}
	res := v.opts.Resolver
	if res == nil {
		res = net.DefaultResolver
	}
	to := v.opts.ResolveTimeout
	if to <= 0 {
		to = defaultResolveTimeout
	}
	hosts := make([]string, 0, len(v.dns))
	for h := range v.dns {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)

	type result struct {
		addrs []netip.Addr
		err   error
	}
	results := make(map[string]result, len(hosts))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, resolveConcurrency)
	for _, h := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(h string) {
			defer wg.Done()
			defer func() { <-sem }()
			ctx, cancel := context.WithTimeout(context.Background(), to)
			defer cancel()
			a, err := res.LookupNetIP(ctx, "ip", h)
			mu.Lock()
			results[h] = result{a, err}
			mu.Unlock()
		}(h)
	}
	wg.Wait()

	for _, h := range hosts {
		r := results[h]
		var msg string
		switch {
		case r.err != nil:
			msg = fmt.Sprintf("host %q cannot be resolved (%v); targets that cannot be checked against the address policy are refused", h, r.err)
		case len(r.addrs) == 0:
			msg = fmt.Sprintf("host %q resolves to no address", h)
		default:
			for _, a := range r.addrs {
				if why := v.tp.denyReason(a); why != "" {
					msg = fmt.Sprintf("host %q resolves to %s: %s", h, a, why)
					break
				}
			}
		}
		if msg == "" {
			continue
		}
		for _, ref := range v.dns[h] {
			v.addErr(ref.index, ref.instance, ref.field, "%s", msg)
		}
	}
}
