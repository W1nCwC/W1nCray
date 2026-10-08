//go:build fallbackroots

package certcfg

// Embedded fallback root CAs. release/build.sh builds the agent with
// -tags fallbackroots (there is no separate "lite" agent program any more),
// and Go prefers the system roots and only falls back to these when none can
// be loaded. That is what lets a device without a CA bundle (a small router, a
// minimal container) still do HTTPS to the panel and the release mirror.
//
// This package is linked by both programs. common/cert carries the same blank
// import, but only the W1nCray-xray kernel links that package, so without this
// file the tag would be a no-op for the agent.
import _ "golang.org/x/crypto/x509roots/fallback"
