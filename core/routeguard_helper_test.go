package core

import (
	"github.com/xtls/xray-core/features/routing"

	"github.com/W1nCwC/W1nCray/app/routeguard"
)

// guardedRouter returns the router as the dispatcher sees it: route selection
// through it is protected against concurrent rule reloads.
func guardedRouter(c *Core) routing.Router {
	return routeguard.Router(c.Rules.router)
}
