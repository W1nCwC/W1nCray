package manifest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
)

const maxDepth = 32

var reInt = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

// Canonical form (the exact bytes that are signed):
//   - the document without its top-level "signature" member;
//   - UTF-8 JSON, no insignificant whitespace;
//   - object members sorted by key, bytewise;
//   - numbers must be integers written without fraction/exponent/leading
//     zeros (the manifest has no other numbers; this removes the usual
//     float-formatting ambiguity of JSON canonicalisation);
//   - strings encoded as Go encoding/json does with HTML escaping off;
//   - duplicate object keys are rejected (parsers disagree on them).
//
// Because the signature covers the generic JSON tree rather than a Go
// struct, unknown members are signed too and cannot be smuggled in.

// parseStrict parses raw into a tree of map[string]any, []any, string,
// json.Number, bool and nil, rejecting duplicate keys, non-integer numbers,
// excessive nesting and trailing data.
func parseStrict(raw []byte) (any, error) {
	if len(raw) > MaxManifestBytes {
		return nil, fmt.Errorf("document larger than %d bytes", MaxManifestBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	v, err := parseValue(dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data after JSON document")
	}
	return v, nil
}

func parseValue(dec *json.Decoder, depth int) (any, error) {
	if depth > maxDepth {
		return nil, errors.New("JSON nested too deeply")
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			obj := map[string]any{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, ok := kt.(string)
				if !ok {
					return nil, errors.New("object key is not a string")
				}
				if _, dup := obj[key]; dup {
					return nil, fmt.Errorf("duplicate object key %q", key)
				}
				val, err := parseValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				obj[key] = val
			}
			if _, err := dec.Token(); err != nil { // '}'
				return nil, err
			}
			return obj, nil
		case '[':
			arr := []any{}
			for dec.More() {
				val, err := parseValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				arr = append(arr, val)
			}
			if _, err := dec.Token(); err != nil { // ']'
				return nil, err
			}
			return arr, nil
		}
		return nil, fmt.Errorf("unexpected delimiter %q", t)
	case json.Number:
		if !reInt.MatchString(t.String()) {
			return nil, fmt.Errorf("number %q is not a plain integer", t.String())
		}
		return t, nil
	default: // string, bool, nil
		return tok, nil
	}
}

// encodeCanonical writes v in canonical form.
func encodeCanonical(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case json.Number:
		buf.WriteString(t.String())
	case string:
		return writeString(buf, t)
	case []any:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := encodeCanonical(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeString(buf, k); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := encodeCanonical(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("unsupported value type %T", v)
	}
	return nil
}

func writeString(buf *bytes.Buffer, s string) error {
	var tmp bytes.Buffer
	enc := json.NewEncoder(&tmp)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return err
	}
	buf.Write(bytes.TrimRight(tmp.Bytes(), "\n"))
	return nil
}

// Canonicalize returns the canonical bytes of the JSON document raw with the
// top-level "signature" member removed. These are the bytes that Sign signs
// and Verify checks.
func Canonicalize(raw []byte) ([]byte, error) {
	tree, err := parseStrict(raw)
	if err != nil {
		return nil, err
	}
	return canonicalOfTree(tree)
}

func canonicalOfTree(tree any) ([]byte, error) {
	obj, ok := tree.(map[string]any)
	if !ok {
		return nil, errors.New("manifest must be a JSON object")
	}
	cp := make(map[string]any, len(obj))
	for k, v := range obj {
		if k != "signature" {
			cp[k] = v
		}
	}
	var buf bytes.Buffer
	if err := encodeCanonical(&buf, cp); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
