package http

import (
	"github.com/labbs/bastion/infrastructure"
	"github.com/labbs/bastion/interfaces/http/app"
	v1 "github.com/labbs/bastion/interfaces/http/v1"
)

func SetupRoutes(deps infrastructure.Deps) {
	logger := deps.Logger.With().Str("component", "http.router").Logger()
	logger.Info().Str("event", "setup_routes").Msg("Setting up HTTP routes")

	// Setup system routes (health, metrics, etc.)
	setupSystemRoutes(deps)

	// Setup v1 routes
	v1.SetupRouterV1(deps)
	app.SetupAppRouter(deps)
}
