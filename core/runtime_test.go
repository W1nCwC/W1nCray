package core

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// The panel's runtime profile (handoff 44) must build exactly the config the
// equivalent files build: same bytes, same rule manager input.
func TestBuildConfigInMemoryMatchesFiles(t *testing.T) {
	files := exampleOptions()
	files.InboundConfigPath = "" // the runtime profile carries no inbounds

	mem := files
	for _, d := range []struct {
		path string
		dst  *json.RawMessage
	}{
		{files.DNSConfigPath, &mem.DNSConfig},
		{files.RouteConfigPath, &mem.RouteConfig},
		{files.OutboundConfigPath, &mem.OutboundConfig},
	} {
		raw, err := readJSONFile(d.path)
		if err != nil {
			t.Fatal(err)
		}
		*d.dst = raw
	}
	// The in-memory documents win: the paths point nowhere.
	missing := filepath.Join(t.TempDir(), "missing.json")
	mem.DNSConfigPath, mem.RouteConfigPath, mem.OutboundConfigPath = missing, missing, missing

	want, wantRM, err := buildConfig(files)
	if err != nil {
		t.Fatal(err)
	}
	got, gotRM, err := buildConfig(mem)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("in-memory config differs from file config:\n got  %s\n want %s", got, want)
	}
	if len(gotRM.global) != len(wantRM.global) || string(gotRM.balancers) != string(wantRM.balancers) {
		t.Fatalf("rule manager input differs: got %d rules, want %d", len(gotRM.global), len(wantRM.global))
	}

	c, err := New(mem)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}

func TestBuildConfigInMemoryInvalidJSON(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(*Options)
		want string
	}{
		{"dns", func(o *Options) { o.DNSConfig = json.RawMessage(`{`) }, "dns config from the panel: invalid JSON"},
		{"route", func(o *Options) { o.RouteConfig = json.RawMessage(`{"rules":`) }, "route config from the panel: invalid JSON"},
		{"outbound", func(o *Options) { o.OutboundConfig = json.RawMessage(`[{]`) }, "custom outbound config from the panel: invalid JSON"},
		{"outbound shape", func(o *Options) { o.OutboundConfig = json.RawMessage(`{"tag":"x"}`) }, "custom outbound config from the panel: json: cannot unmarshal"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := goldenOptions()
			tc.set(&opts)
			_, _, err := buildConfig(opts)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

// File mode keeps its exact error texts (callers and logs match on them).
func TestBuildConfigFileErrorsUnchanged(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.json")
	for _, tc := range []struct {
		set  func(*Options)
		want string
	}{
		{func(o *Options) { o.DNSConfigPath = missing }, "dns config: open "},
		{func(o *Options) { o.RouteConfigPath = missing }, "route config: open "},
		{func(o *Options) { o.OutboundConfigPath = missing }, "custom outbound config: open "},
	} {
		opts := goldenOptions()
		tc.set(&opts)
		_, _, err := buildConfig(opts)
		if err == nil || !strings.HasPrefix(err.Error(), tc.want) {
			t.Fatalf("err = %v, want prefix %q", err, tc.want)
		}
	}
}
