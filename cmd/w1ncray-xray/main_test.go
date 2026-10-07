package main

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

// TestStagedResultJSON pins the JSON document `check-staged` prints: the
// contract the agent relies on (X2) is {"ok":bool,"errors":[{"file","message"}]}.
func TestStagedResultJSON(t *testing.T) {
	res := stagedResult{
		OK: false,
		Errors: stagedErrors([]error{
			errors.New("route.json: rules[0] unknown field"),
			errors.New("xray instance pre-check: duplicate tag \"node173\""),
		}),
	}
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"ok":false,"errors":[{"file":"route.json","message":"rules[0] unknown field"},{"file":"","message":"xray instance pre-check: duplicate tag \"node173\""}]}`
	if string(b) != want {
		t.Errorf("staged result = %s, want %s", b, want)
	}

	ok := stagedResult{OK: true, Errors: stagedErrors(nil)}
	b, err = json.Marshal(ok)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"ok":true,"errors":[]}` {
		t.Errorf("empty result = %s, want {\"ok\":true,\"errors\":[]}", b)
	}
}

// TestSplitNames parses the --files list, ignoring empty entries and spaces.
func TestSplitNames(t *testing.T) {
	got := splitNames(" route.json , dns.json ,, config.yml ")
	want := []string{"route.json", "dns.json", "config.yml"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("splitNames = %v, want %v", got, want)
	}
	if got := splitNames("  ,  "); len(got) != 0 {
		t.Errorf("splitNames of blanks = %v, want empty", got)
	}
}
