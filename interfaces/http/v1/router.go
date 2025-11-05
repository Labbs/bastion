package v1

import (
	"github.com/labbs/bastion/infrastructure"
	"github.com/labbs/bastion/interfaces/http/v1/admin"
	"github.com/labbs/bastion/interfaces/http/v1/app"
	"github.com/labbs/bastion/interfaces/http/v1/auth"
	"github.com/labbs/bastion/interfaces/http/v1/user"
)

func SetupRouterV1(deps infrastructure.Deps) {
	deps.Logger.Info().Str("component", "http.router.v1").Msg("Setting up API v1 routes")
	grp := deps.Http.FiberOapi.Group("/api/v1")

	authCtrl := auth.Controller{
		Config:    deps.Config,
		Logger:    deps.Logger,
		FiberOapi: grp.Group("/auth"),
		AuthApp:   deps.AuthApp,
	}
	auth.SetupAuthRouter(authCtrl)

	userCtrl := user.Controller{
		Config:    deps.Config,
		Logger:    deps.Logger,
		FiberOapi: grp.Group("/user"),
		UserApp:   deps.UserApp,
	}
	user.SetupUserRouter(userCtrl)

	app.SetupAppRouter(deps)

	// Admin routes (require admin role)
	admin.SetupAdminRouter(deps)
}
