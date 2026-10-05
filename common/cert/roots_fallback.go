//go:build fallbackroots

package cert

// Embedded root CAs for devices without a CA bundle (small routers). Go
// prefers the system roots and only uses these when none can be loaded.
import _ "golang.org/x/crypto/x509roots/fallback"
