package main

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/W1nCwC/W1nCray/kernel/manifest"
)

// reTargetV052 is v0.5.2's manifest target-key rule, copied verbatim from
//
//	git show v0.5.2:kernel/manifest/manifest.go
//	  reTarget = ^[a-z0-9]{2,16}/[a-z0-9]{2,16}$
//
// A "+suffix" key (the legacy "linux/amd64+openwrt" spelling) can never match
// it: "+" is not in [a-z0-9]. That is why the OpenWrt lite builds moved to the
// openwrt_targets field, which a v0.5.2 decoder ignores (sign.go decodes with
// encoding/json and does not call DisallowUnknownFields).
var reTargetV052 = regexp.MustCompile(`^[a-z0-9]{2,16}/[a-z0-9]{2,16}$`)

// checkLegacyV052 is the 0.5.x compatibility gate. It mirrors
// kernel/manifest/manifest_test.go's legacyV052Validate (the minimal faithful
// replica of v0.5.2's Kernel.validate):
//
//   - the document must list at least one kernel;
//   - every kernel must have at least one "targets" key (v0.5.2 reports
//     "no targets" for an empty targets object);
//   - every "targets" key must match reTargetV052, so no "+suffix" key.
//
// v0.5.2 returns ErrManifestInvalid on the first violation and rejects the
// WHOLE document, not just the offending entry: every command on such an agent
// then reports no_manifest. manifestgen therefore runs this gate on the final
// manifest before it is signed. It is on by default; the only way to skip it is
// the explicit --no-legacy-gate command-line flag (see README.md).
func checkLegacyV052(m *manifest.Manifest) error {
	if len(m.Kernels) == 0 {
		return errors.New(`legacy 0.5.x gate: the manifest lists no kernels; v0.5.2 rejects the whole document ("no kernels"), so a 0.5.x agent would load nothing and report no_manifest on every command`)
	}
	for i := range m.Kernels {
		k := &m.Kernels[i]
		if len(k.Targets) == 0 {
			return fmt.Errorf(`legacy 0.5.x gate: kernel %s %s has no "targets" entries (only openwrt_targets); v0.5.2 rejects the WHOLE manifest with "no targets" when any kernel's targets object is empty, so a 0.5.x agent would load no kernel at all (kernel_install, self_update and every signed-manifest command would report no_manifest). Give %s at least one plain "os/arch" key in targets, or pass --no-legacy-gate to emit a manifest that 0.5.x cannot read`,
				k.Name, k.Version, k.Name)
		}
		for key := range k.Targets {
			if reTargetV052.MatchString(key) {
				continue
			}
			if strings.Contains(key, "+") {
				return fmt.Errorf(`legacy 0.5.x gate: kernel %s %s: targets key %q carries a "+" suffix, which v0.5.2's reTarget %s does not accept; v0.5.2 rejects the WHOLE manifest on the first bad key (the entry is not skipped), so a 0.5.x agent would load nothing. Put the OpenWrt build in openwrt_targets (or set openwrt: true on the local entry), or pass --no-legacy-gate to emit a manifest that 0.5.x cannot read`,
					k.Name, k.Version, key, reTargetV052)
			}
			return fmt.Errorf(`legacy 0.5.x gate: kernel %s %s: targets key %q does not match v0.5.2's reTarget %s; v0.5.2 rejects the WHOLE manifest on the first bad key (the entry is not skipped), so a 0.5.x agent would load nothing. Use a plain "os/arch" key, or pass --no-legacy-gate to emit a manifest that 0.5.x cannot read`,
				k.Name, k.Version, key, reTargetV052)
		}
	}
	return nil
}
