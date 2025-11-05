package app

import (
	"github.com/labbs/bastion/application"
	"github.com/labbs/bastion/infrastructure"
	"github.com/labbs/bastion/infrastructure/config"
	fiberoapi "github.com/labbs/fiber-oapi"
	"github.com/rs/zerolog"
)

type Controller struct {
	Config  config.Config
	Logger  zerolog.Logger
	FiberOapi *fiberoapi.OApiGroup
	AppApp  *application.AppApp
}

func SetupAppRouter(deps infrastructure.Deps) {
	deps.Logger.Info().Str("component", "http.router.v1.app").Msg("Setting up API v1 app routes")
	grp := deps.Http.FiberOapi.Group("/api/v1")

	appCtrl := Controller{
		Config:    deps.Config,
		Logger:    deps.Logger,
		FiberOapi: grp.Group("/apps"),
		AppApp:    deps.AppApp,
	}

	fiberoapi.Get(appCtrl.FiberOapi, "", appCtrl.GetApps, fiberoapi.OpenAPIOptions{
		Summary:     "Get available apps",
		Description: "Get list of available web applications for the authenticated user",
		OperationID: "app.get_apps",
		Tags:        []string{"Apps"},
	})

	fiberoapi.Get(appCtrl.FiberOapi, "/:id", appCtrl.GetApp, fiberoapi.OpenAPIOptions{
		Summary:     "Get app by ID",
		Description: "Get a specific web application by ID",
		OperationID: "app.get_app",
		Tags:        []string{"Apps"},
	})
}

