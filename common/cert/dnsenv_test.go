package cert

import (
	"os"
	"testing"
)

// The config loader lower-cases map keys; lego reads upper-case variables.
func TestApplyDNSEnvUpperCasesNames(t *testing.T) {
	t.Setenv("W1NC_TEST_DNS_KEY", "") // ensure restoration of a known name below
	defer os.Unsetenv("W1NC_TEST_DNS_KEY")
	defer os.Unsetenv("W1NC_TEST_DNS_EMAIL")

	applyDNSEnv(map[string]string{
		"w1nc_test_dns_key":     "k1",
		" W1NC_TEST_DNS_EMAIL ": "e1", // already upper-case, with stray spaces
	})

	if got := os.Getenv("W1NC_TEST_DNS_KEY"); got != "k1" {
		t.Fatalf("W1NC_TEST_DNS_KEY = %q, want k1", got)
	}
	if got := os.Getenv("W1NC_TEST_DNS_EMAIL"); got != "e1" {
		t.Fatalf("W1NC_TEST_DNS_EMAIL = %q, want e1", got)
	}
}
