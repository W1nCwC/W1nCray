package xraynode

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/W1nCwC/W1nCray/core"
)

// seedConfigFiles creates the optional JSON files that opts still reads from
// disk when they do not exist yet, each with the empty document that means
// "nothing configured": routing without rules, no custom inbound, no custom
// outbound, no DNS.
//
// Why: a fresh install writes config.yml with RouteConfigPath,
// InboundConfigPath and OutboundConfigPath set, but nothing creates those
// files, and core.New fails on a missing one. The kernel service then
// crash-looped (restart counter 400+ on a new machine) and, because the
// managed-file apply refuses a file set whose other files are missing, the
// administrator could not even push the missing files from the panel.
//
// core.CheckFiles keeps reporting a missing file for `W1nCray check`, so a
// typo in a path stays visible there; only the running kernel seeds. A
// directory that does not exist is left alone (it is a wrong path, not a
// fresh install), and an existing file is never touched. Failures are
// returned so the caller can log them; core.New then reports the real error.
func seedConfigFiles(opts *core.Options) []error {
	var errs []error
	seed := func(path, content string) {
		if path == "" {
			return
		}
		if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
			return
		}
		if st, err := os.Stat(filepath.Dir(path)); err != nil || !st.IsDir() {
			return
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			if !errors.Is(err, fs.ErrExist) {
				errs = append(errs, err)
			}
			return
		}
		_, werr := f.WriteString(content)
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			errs = append(errs, werr)
		}
	}
	seed(opts.DNSConfigPath, "{}\n")
	seed(opts.RouteConfigPath, "{\"domainStrategy\":\"AsIs\",\"rules\":[]}\n")
	seed(opts.InboundConfigPath, "[]\n")
	seed(opts.OutboundConfigPath, "[]\n")
	return errs
}
