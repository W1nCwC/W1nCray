package gost

import (
	"bufio"
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

// promSample is one sample of the Prometheus text exposition format.
type promSample struct {
	name   string
	labels map[string]string
	value  float64
}

// parseProm is a minimal parser for the Prometheus text format (version
// 0.0.4): comment lines are skipped, samples are
//
//	name{label="value",...} value [timestamp]
//
// Label values may contain the escapes \\ \" \n. It is deliberately small
// (the driver only needs a handful of gost series) so no dependency is added.
func parseProm(b []byte) ([]promSample, error) {
	var out []promSample
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	ln := 0
	for sc.Scan() {
		ln++
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		s, err := parsePromLine(line)
		if err != nil {
			return nil, fmt.Errorf("metrics line %d: %w", ln, err)
		}
		out = append(out, s)
	}
	return out, sc.Err()
}

func parsePromLine(line string) (promSample, error) {
	s := promSample{labels: map[string]string{}}
	i := 0
	for i < len(line) && line[i] != '{' && line[i] != ' ' && line[i] != '\t' {
		i++
	}
	s.name = line[:i]
	if s.name == "" {
		return s, fmt.Errorf("missing metric name")
	}
	if i < len(line) && line[i] == '{' {
		i++
		for {
			for i < len(line) && (line[i] == ' ' || line[i] == ',') {
				i++
			}
			if i >= len(line) {
				return s, fmt.Errorf("unterminated label set")
			}
			if line[i] == '}' {
				i++
				break
			}
			j := i
			for j < len(line) && line[j] != '=' {
				j++
			}
			if j+1 >= len(line) || line[j+1] != '"' {
				return s, fmt.Errorf("malformed label")
			}
			key := strings.TrimSpace(line[i:j])
			j += 2
			var val strings.Builder
			for {
				if j >= len(line) {
					return s, fmt.Errorf("unterminated label value")
				}
				c := line[j]
				if c == '\\' && j+1 < len(line) {
					switch line[j+1] {
					case 'n':
						val.WriteByte('\n')
					default:
						val.WriteByte(line[j+1])
					}
					j += 2
					continue
				}
				if c == '"' {
					j++
					break
				}
				val.WriteByte(c)
				j++
			}
			s.labels[key] = val.String()
			i = j
		}
	}
	fields := strings.Fields(line[i:])
	if len(fields) < 1 || len(fields) > 2 {
		return s, fmt.Errorf("malformed value")
	}
	v, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return s, fmt.Errorf("bad value %q", fields[0])
	}
	s.value = v
	return s, nil
}
