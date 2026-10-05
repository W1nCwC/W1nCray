package realm

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/spec"
)

// Render is a pure, deterministic function of the instance and the driver
// options. The only file is realm.json (realm reads JSON when the text is not
// TOML; a JSON document is never valid TOML, so the fallback is unambiguous).
// It may contain the derived ws path token and certificate paths, so whoever
// writes it must use mode 0600.
func (d *Driver) Render(in spec.Instance) (driver.Artifact, error) {
	p, err := d.buildPlan(in)
	if err != nil {
		return driver.Artifact{}, err
	}
	cfg := fileConf{Log: logConf{Level: "warn"}, Endpoints: p.endpoints}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(cfg); err != nil {
		return driver.Artifact{}, err
	}
	files := map[string][]byte{configName: buf.Bytes()}
	claims := append([]driver.PortClaim(nil), p.claims...)
	sortedClaims(claims)
	return driver.Artifact{Files: files, Hash: hashFiles(files), PortClaims: claims}, nil
}

// hashFiles hashes the artifact version, the argument vector shape and every
// file (sorted by name, length-prefixed) so equal inputs give equal hashes.
func hashFiles(files map[string][]byte) string {
	h := sha256.New()
	h.Write([]byte(artifactVersion))
	h.Write([]byte("\x00args:-c <" + configName + ">\x00"))
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		h.Write([]byte(n))
		h.Write([]byte{0})
		h.Write([]byte(strconv.Itoa(len(files[n]))))
		h.Write([]byte{0})
		h.Write(files[n])
	}
	return hex.EncodeToString(h.Sum(nil))
}
