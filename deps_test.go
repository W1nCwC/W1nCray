package main

import (
	"os/exec"
	"strings"
	"testing"
)

// TestAgentDoesNotLinkXrayCore is the WP-X1 guard: the agent program must not
// depend on Xray-core. The Xray instance lives in the separate W1nCray-xray
// program, and a regression here would quietly put ~78 MiB of kernel back into
// every agent install.
//
// The check shells out to `go list -deps`, which lists the transitive package
// dependencies of a package without building it.
func TestAgentDoesNotLinkXrayCore(t *testing.T) {
	deps := goListDeps(t, ".")

	if pkg := firstXrayDep(deps); pkg != "" {
		t.Errorf("the agent main package depends on %s:\n%s", pkg, strings.Join(xrayDeps(deps), "\n"))
	}
}

// TestXrayKernelLinksXrayCore is the other half of the guard: the kernel
// program must depend on Xray-core (otherwise the split would have produced two
// agents and no kernel).
func TestXrayKernelLinksXrayCore(t *testing.T) {
	deps := goListDeps(t, "./cmd/w1ncray-xray")
	if firstXrayDep(deps) == "" {
		t.Errorf("./cmd/w1ncray-xray does not depend on github.com/xtls/xray-core")
	}
}

// TestAgentDoesNotLinkACME is the WP-X2 guard: the agent program must not link
// go-acme/lego (nor the dozens of cloud DNS SDKs its DNS-01 providers pull in).
// The certificate *configuration* lives in common/certcfg, which is lego-free;
// only the Xray kernel program links common/cert and lego.
func TestAgentDoesNotLinkACME(t *testing.T) {
	deps := goListDeps(t, ".")
	if pkg := firstACMEDep(deps); pkg != "" {
		t.Errorf("the agent main package depends on %s:\n%s", pkg, strings.Join(acmeDeps(deps), "\n"))
	}
}

// goListDeps returns the transitive dependencies of pkg, one per line.
func goListDeps(t *testing.T, pkg string) []string {
	t.Helper()
	out, err := exec.Command("go", "list", "-deps", pkg).Output()
	if err != nil {
		t.Fatalf("go list -deps %s: %v", pkg, err)
	}
	var deps []string
	for _, line := range strings.Split(string(out), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			deps = append(deps, line)
		}
	}
	if len(deps) == 0 {
		t.Fatalf("go list -deps %s returned nothing", pkg)
	}
	return deps
}

// xrayDeps returns every dependency that belongs to Xray-core.
func xrayDeps(deps []string) []string {
	var out []string
	for _, d := range deps {
		if d == "github.com/xtls/xray-core" || strings.HasPrefix(d, "github.com/xtls/xray-core/") {
			out = append(out, d)
		}
	}
	return out
}

// firstXrayDep returns the first Xray-core dependency, or "".
func firstXrayDep(deps []string) string {
	if out := xrayDeps(deps); len(out) > 0 {
		return out[0]
	}
	return ""
}

// acmeDeps returns every dependency that belongs to go-acme/lego.
func acmeDeps(deps []string) []string {
	var out []string
	for _, d := range deps {
		if d == "github.com/go-acme/lego/v4" || strings.HasPrefix(d, "github.com/go-acme/lego/") {
			out = append(out, d)
		}
	}
	return out
}

// firstACMEDep returns the first go-acme/lego dependency, or "".
func firstACMEDep(deps []string) string {
	if out := acmeDeps(deps); len(out) > 0 {
		return out[0]
	}
	return ""
}
