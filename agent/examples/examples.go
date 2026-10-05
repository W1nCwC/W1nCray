// Package examples ships runnable desired-state samples for the W1nCray agent.
//
// Every file under testdata is a complete spec.Desired (version 1) that can be
// copied to the machine and passed to `W1nCray agent-apply -f`, or pointed at
// by Agent.DesiredPath. The tests of this package keep the samples honest: each
// one must pass the schema and policy validator, and each instance must be
// accepted and rendered by the driver of its engine. A sample that drifts away
// from the code therefore fails the build instead of misleading an operator.
//
// The samples are documentation: docs/AGENT.md indexes them. They contain
// placeholder secrets that must be replaced before real use.
package examples

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/W1nCwC/W1nCray/agent/spec"
)

//go:embed testdata/*.json
var files embed.FS

// Example is one embedded sample.
type Example struct {
	// Name is the file name without the ".json" suffix, for example
	// "forward-tcp".
	Name string
	// File is the file name inside testdata, for example "forward-tcp.json".
	File string
	// Desired is the decoded sample.
	Desired spec.Desired
}

// List returns every sample sorted by name. It panics if an embedded file does
// not decode: that is a packaging error caught by the tests, never a runtime
// condition.
func List() []Example {
	entries, err := files.ReadDir("testdata")
	if err != nil {
		panic("examples: " + err.Error())
	}
	var out []Example
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		raw, err := files.ReadFile("testdata/" + e.Name())
		if err != nil {
			panic("examples: " + err.Error())
		}
		d, err := Decode(raw)
		if err != nil {
			panic(fmt.Sprintf("examples: %s: %v", e.Name(), err))
		}
		out = append(out, Example{
			Name:    strings.TrimSuffix(e.Name(), ".json"),
			File:    e.Name(),
			Desired: d,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Raw returns the bytes of an embedded sample by file name.
func Raw(file string) ([]byte, error) {
	return files.ReadFile("testdata/" + file)
}

// Decode strictly decodes a desired state: unknown fields and trailing data
// are errors, exactly like the agent does when it reads a desired-state file.
func Decode(raw []byte) (spec.Desired, error) {
	var d spec.Desired
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return spec.Desired{}, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return spec.Desired{}, fmt.Errorf("trailing data after the desired state")
	}
	return d, nil
}
