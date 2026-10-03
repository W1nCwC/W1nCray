package core

import (
	"encoding/json"
	"fmt"

	"github.com/xtls/xray-core/infra/conf"
)

// CheckFiles validates every JSON file referenced by opts separately, so that
// errors name the file and the entry. It complements New, whose errors come
// from the combined config.
func CheckFiles(opts Options) []error {
	var errs []error
	fail := func(file string, format string, a ...any) {
		errs = append(errs, fmt.Errorf("%s: %s", file, fmt.Sprintf(format, a...)))
	}

	if f := opts.DNSConfigPath; f != "" {
		if raw, err := readJSONFile(f); err != nil {
			errs = append(errs, err)
		} else {
			var c conf.DNSConfig
			if err := json.Unmarshal(raw, &c); err != nil {
				fail(f, "%v", err)
			} else if _, err := c.Build(); err != nil {
				fail(f, "%v", err)
			}
		}
	}

	if f := opts.RouteConfigPath; f != "" {
		if raw, err := readJSONFile(f); err != nil {
			errs = append(errs, err)
		} else {
			var c conf.RouterConfig
			if err := json.Unmarshal(raw, &c); err != nil {
				fail(f, "%v", err)
			} else {
				// Build rule by rule to point at the broken one.
				for i, r := range c.RuleList {
					one := conf.RouterConfig{RuleList: []json.RawMessage{r}, Balancers: c.Balancers}
					pb, err := one.Build()
					if err == nil {
						_, err = pb.Rule[0].BuildCondition()
					}
					if err != nil {
						fail(f, "rules[%d] %s: %v", i, compact(r), err)
					}
				}
			}
		}
	}

	if f := opts.InboundConfigPath; f != "" {
		if raw, err := readJSONFile(f); err != nil {
			errs = append(errs, err)
		} else {
			var list []json.RawMessage
			if err := json.Unmarshal(raw, &list); err != nil {
				fail(f, "must be a JSON array: %v", err)
			}
			for i, r := range list {
				var c conf.InboundDetourConfig
				if err := json.Unmarshal(r, &c); err != nil {
					fail(f, "[%d]: %v", i, err)
				} else if _, err := c.Build(); err != nil {
					fail(f, "[%d] tag=%q: %v", i, c.Tag, err)
				}
			}
		}
	}

	if f := opts.OutboundConfigPath; f != "" {
		if raw, err := readJSONFile(f); err != nil {
			errs = append(errs, err)
		} else {
			var list []json.RawMessage
			if err := json.Unmarshal(raw, &list); err != nil {
				fail(f, "must be a JSON array: %v", err)
			}
			for i, r := range list {
				var c conf.OutboundDetourConfig
				if err := json.Unmarshal(r, &c); err != nil {
					fail(f, "[%d]: %v", i, err)
				} else if _, err := c.Build(); err != nil {
					fail(f, "[%d] tag=%q: %v", i, c.Tag, err)
				}
			}
		}
	}
	return errs
}

func compact(raw json.RawMessage) string {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return string(raw)
	}
	b, _ := json.Marshal(v)
	if len(b) > 160 {
		return string(b[:157]) + "..."
	}
	return string(b)
}
