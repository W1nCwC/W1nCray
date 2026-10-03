// W1nCray is an Xboard node backend built on the official Xray-core,
// rewritten from XrayR.
package main

import (
	"embed"
	"io/fs"

	"github.com/W1nCwC/W1nCray/cmd"
)

// defaults are the example files written by `W1nCray init`.
//
//go:embed release/config/config.yml.example release/config/dns.json release/config/route.json release/config/custom_inbound.json release/config/custom_outbound.json release/config/rulelist
var defaults embed.FS

func main() {
	sub, err := fs.Sub(defaults, "release/config")
	if err != nil {
		panic(err)
	}
	cmd.SetDefaultFiles(sub)
	cmd.Execute()
}
