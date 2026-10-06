package panelclient

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/W1nCwC/W1nCray/agent/spec"
)

// TestDesiredWithFilesStillDecodesStrictly covers acceptance 1: the desired
// state's new "files" section passes the strict decoder (no unknown field), and
// a typo inside it is still rejected — the panel can only put the key in a
// revision for an agent that declared the capability (ruling 1).
func TestDesiredWithFilesStillDecodesStrictly(t *testing.T) {
	body := `{"version":1,"revision":7,"instances":[],"files":[` +
		`{"name":"route.json","sha256":"` + strings.Repeat("a", 64) + `","size":12},` +
		`{"name":"geoip.dat","sha256":"` + strings.Repeat("b", 64) + `","size":1024,"kernel":"xray"}]}`

	resp := ConfigResponse{Revision: 7, DesiredRaw: json.RawMessage(body)}
	d, err := resp.Desired()
	if err != nil {
		t.Fatalf("a desired state with files was rejected: %v", err)
	}
	if len(d.Files) != 2 {
		t.Fatalf("files = %+v", d.Files)
	}
	if d.Files[0].Name != "route.json" || d.Files[0].Size != 12 {
		t.Errorf("files[0] = %+v", d.Files[0])
	}
	if d.Files[1].Kernel != "xray" {
		t.Errorf("files[1] = %+v", d.Files[1])
	}

	// An unknown key inside the new section is still an error.
	bad := ConfigResponse{Revision: 7, DesiredRaw: json.RawMessage(
		`{"version":1,"revision":7,"instances":[],"files":[{"name":"route.json","sha256":"` +
			strings.Repeat("a", 64) + `","size":12,"url":"http://evil"}]}`)}
	if _, err := bad.Desired(); err == nil {
		t.Fatal("an unknown key inside files was accepted")
	}
}

// TestDesiredFilesRoundTrip marshals and re-decodes the section, so the wire
// names cannot drift from spec.FileRef.
func TestDesiredFilesRoundTrip(t *testing.T) {
	in := spec.Desired{
		Version: 1, Revision: 3,
		Files: []spec.FileRef{{Name: "dns.json", SHA256: strings.Repeat("c", 64), Size: 5}},
	}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"files"`) {
		t.Fatalf("marshalled desired has no files key: %s", raw)
	}
	resp := ConfigResponse{Revision: 3, DesiredRaw: raw}
	out, err := resp.Desired()
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if len(out.Files) != 1 || out.Files[0] != in.Files[0] {
		t.Errorf("files = %+v, want %+v", out.Files, in.Files)
	}
	// An absent files section is valid and empty.
	resp = ConfigResponse{Revision: 1, DesiredRaw: json.RawMessage(`{"version":1,"revision":1,"instances":[]}`)}
	out, err = resp.Desired()
	if err != nil {
		t.Fatalf("a desired state without files was rejected: %v", err)
	}
	if len(out.Files) != 0 {
		t.Errorf("files = %+v, want none", out.Files)
	}
}
