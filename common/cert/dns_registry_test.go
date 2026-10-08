package cert

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/W1nCwC/W1nCray/common/certcfg"
)

// The static provider lists in common/certcfg are what the lego-free agent uses
// to answer "is this DNS-01 provider in this build?". They are only correct if
// they match lego's generated registry, so this test — the one place that may
// link lego — reads that registry and compares.

// reRegistryCase matches the "case \"a\", \"b\":" lines of lego's generated
// registry (providers/dns/zz_gen_dns_providers.go).
var reRegistryCase = regexp.MustCompile(`(?m)^\tcase ((?:"[^"]+"(?:, )?)+):`)

// reQuotedName matches one quoted provider name.
var reQuotedName = regexp.MustCompile(`"([^"]+)"`)

// legoRegistryNames returns every name lego's DNS-01 factory accepts, sorted.
// It reads the module's generated source; the module directory comes from
// `go list -m`, the same tool the rest of the test suite uses.
func legoRegistryNames(t *testing.T) []string {
	t.Helper()
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/go-acme/lego/v4").Output()
	if err != nil {
		t.Fatalf("go list -m github.com/go-acme/lego/v4: %v", err)
	}
	dir := strings.TrimSpace(string(out))
	if dir == "" {
		t.Fatal("go list -m returned no module directory for github.com/go-acme/lego/v4")
	}
	path := filepath.Join(dir, "providers", "dns", "zz_gen_dns_providers.go")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading lego's DNS registry %s: %v", path, err)
	}
	var names []string
	for _, m := range reRegistryCase.FindAllStringSubmatch(string(raw), -1) {
		for _, q := range reQuotedName.FindAllStringSubmatch(m[1], -1) {
			names = append(names, q[1])
		}
	}
	if len(names) == 0 {
		t.Fatalf("no provider names found in %s", path)
	}
	sort.Strings(names)
	return names
}

// sortedCopy returns a sorted copy of names.
func sortedCopy(names []string) []string {
	out := append([]string(nil), names...)
	sort.Strings(out)
	return out
}

// TestDNSProviderListMatchesLegoRegistry is the consistency guard: the full
// build's static list must be exactly lego's registry (a missing name would
// reject a provider that works, an extra one would accept one that cannot be
// built), and the lite build's list must be a subset of it.
func TestDNSProviderListMatchesLegoRegistry(t *testing.T) {
	registry := legoRegistryNames(t)
	registrySet := map[string]bool{}
	for _, n := range registry {
		registrySet[n] = true
	}
	ours := sortedCopy(certcfg.DNSProviderNames())

	switch certcfg.BuildFlavor {
	case "full":
		if strings.Join(ours, ",") != strings.Join(registry, ",") {
			missing, extra := diffSets(registrySet, ours)
			t.Fatalf("the full provider list does not match lego's registry\nmissing from ours: %v\nnot in lego: %v", missing, extra)
		}
	case "lite":
		for _, n := range ours {
			if !registrySet[n] {
				t.Errorf("lite provider %q is not in lego's registry", n)
			}
		}
		if len(ours) == 0 {
			t.Fatal("the lite provider list is empty")
		}
	case "none":
		if len(ours) != 0 {
			t.Fatalf("the none build lists providers: %v", ours)
		}
	default:
		t.Fatalf("unknown build flavor %q", certcfg.BuildFlavor)
	}

	// DNSProviderSupported must agree with the list for every name, and an
	// unknown name must never be reported as supported.
	for _, n := range append(ours, "no-such-provider", "") {
		want := false
		for _, o := range ours {
			if o == n {
				want = true
				break
			}
		}
		if got := certcfg.DNSProviderSupported(n); got != want {
			t.Errorf("certcfg.DNSProviderSupported(%q) = %v, want %v", n, got, want)
		}
		if got := DNSProviderSupported(n); got != want {
			t.Errorf("cert.DNSProviderSupported(%q) = %v, want %v", n, got, want)
		}
	}
}

// diffSets reports the registry names our list is missing and the names our
// list has that the registry does not.
func diffSets(registrySet map[string]bool, ours []string) (missing, extra []string) {
	ourSet := map[string]bool{}
	for _, n := range ours {
		ourSet[n] = true
		if !registrySet[n] {
			extra = append(extra, n)
		}
	}
	for n := range registrySet {
		if !ourSet[n] {
			missing = append(missing, n)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	return missing, extra
}
