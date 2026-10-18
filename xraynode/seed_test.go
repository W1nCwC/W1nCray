package xraynode

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/W1nCwC/W1nCray/core"
)

func TestSeedConfigFiles(t *testing.T) {
	dir := t.TempDir()
	opts := core.Options{
		LogLevel:           "warning",
		DNSConfigPath:      filepath.Join(dir, "dns.json"),
		RouteConfigPath:    filepath.Join(dir, "route.json"),
		InboundConfigPath:  filepath.Join(dir, "custom_inbound.json"),
		OutboundConfigPath: filepath.Join(dir, "custom_outbound.json"),
		Connection:         core.ConnectionPolicy{Handshake: 4, ConnIdle: 30, UplinkOnly: 2, DownlinkOnly: 4, BufferSize: 64},
	}
	// An existing file is never touched.
	keep := []byte(`{"rules":[]}` + "\n")
	if err := os.WriteFile(opts.RouteConfigPath, keep, 0o644); err != nil {
		t.Fatal(err)
	}
	if errs := seedConfigFiles(&opts); len(errs) != 0 {
		t.Fatal(errs)
	}
	got, _ := os.ReadFile(opts.RouteConfigPath)
	if string(got) != string(keep) {
		t.Fatalf("route.json was rewritten: %q", got)
	}
	for _, p := range []string{opts.DNSConfigPath, opts.InboundConfigPath, opts.OutboundConfigPath} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s not seeded: %v", p, err)
		}
	}
	// The seeded set builds an instance with the default outbounds.
	c, err := core.New(opts)
	if err != nil {
		t.Fatalf("seeded files must be accepted: %v", err)
	}
	c.Close()
	if errs := core.CheckFiles(opts); len(errs) != 0 {
		t.Fatalf("seeded files must pass the check: %v", errs)
	}
}

func TestSeedConfigFilesIgnoresMissingDirectory(t *testing.T) {
	opts := core.Options{RouteConfigPath: filepath.Join(t.TempDir(), "nope", "route.json")}
	if errs := seedConfigFiles(&opts); len(errs) != 0 {
		t.Fatal(errs)
	}
	if _, err := os.Stat(opts.RouteConfigPath); err == nil {
		t.Fatal("a file in a missing directory must not be created")
	}
}
