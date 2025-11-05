package admin

import (
	"github.com/gofiber/fiber/v2"
	"github.com/labbs/bastion/application"
	"github.com/labbs/bastion/infrastructure"
	"github.com/labbs/bastion/infrastructure/config"
	fiberoapi "github.com/labbs/fiber-oapi"
	"github.com/rs/zerolog"
)

type Controller struct {
	Config    config.Config
	Logger    zerolog.Logger
	FiberOapi *fiberoapi.OApiGroup
	AdminApp  *application.AdminApp
	UserApp   *application.UserApp
	SessionApp *application.SessionApp
}

// adminOnlyMiddleware checks if the user has admin role
func adminOnlyMiddleware(sessionApp *application.SessionApp, logger zerolog.Logger) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		authCtx, err := fiberoapi.GetAuthContext(ctx)
		if err != nil {
			logger.Error().Err(err).Msg("failed to get auth context")
			return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Authentication required",
			})
		}

		if !sessionApp.HasRole(authCtx, "admin") {
			logger.Warn().Str("user_id", authCtx.UserID).Msg("non-admin user attempted to access admin route")
			return ctx.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "Admin access required",
			})
		}

		return ctx.Next()
	}
}

func SetupAdminRouter(deps infrastructure.Deps) {
	deps.Logger.Info().Str("component", "http.router.v1.admin").Msg("Setting up API v1 admin routes")
	
	// Add admin-only middleware to Fiber directly
	adminGroup := deps.Http.Fiber.Group("/api/v1/admin")
	adminGroup.Use(adminOnlyMiddleware(deps.SessionApp, deps.Logger))
	
	// Create OApiGroup for OpenAPI routes
	grp := deps.Http.FiberOapi.Group("/api/v1/admin")

	adminCtrl := Controller{
		Config:     deps.Config,
		Logger:     deps.Logger,
		FiberOapi:  grp,
		AdminApp:   deps.AdminApp,
		UserApp:    deps.UserApp,
		SessionApp: deps.SessionApp,
	}

	// Host management
	fiberoapi.Post(adminCtrl.FiberOapi, "/hosts", adminCtrl.CreateHost, fiberoapi.OpenAPIOptions{
		Summary:     "Create host",
		Description: "Create a new SSH host (admin only)",
		OperationID: "admin.create_host",
		Tags:        []string{"Admin"},
	})

	fiberoapi.Get(adminCtrl.FiberOapi, "/hosts", adminCtrl.GetHosts, fiberoapi.OpenAPIOptions{
		Summary:     "Get all hosts",
		Description: "Get all SSH hosts (admin only)",
		OperationID: "admin.get_hosts",
		Tags:        []string{"Admin"},
	})

	fiberoapi.Put(adminCtrl.FiberOapi, "/hosts/:id", adminCtrl.UpdateHost, fiberoapi.OpenAPIOptions{
		Summary:     "Update host",
		Description: "Update an SSH host (admin only)",
		OperationID: "admin.update_host",
		Tags:        []string{"Admin"},
	})

	fiberoapi.Delete(adminCtrl.FiberOapi, "/hosts/:id", adminCtrl.DeleteHost, fiberoapi.OpenAPIOptions{
		Summary:     "Delete host",
		Description: "Delete an SSH host (admin only)",
		OperationID: "admin.delete_host",
		Tags:        []string{"Admin"},
	})

	// App management
	fiberoapi.Post(adminCtrl.FiberOapi, "/apps", adminCtrl.CreateApp, fiberoapi.OpenAPIOptions{
		Summary:     "Create app",
		Description: "Create a new web app (admin only)",
		OperationID: "admin.create_app",
		Tags:        []string{"Admin"},
	})

	fiberoapi.Get(adminCtrl.FiberOapi, "/apps", adminCtrl.GetApps, fiberoapi.OpenAPIOptions{
		Summary:     "Get all apps",
		Description: "Get all web apps (admin only)",
		OperationID: "admin.get_apps",
		Tags:        []string{"Admin"},
	})

	fiberoapi.Put(adminCtrl.FiberOapi, "/apps/:id", adminCtrl.UpdateApp, fiberoapi.OpenAPIOptions{
		Summary:     "Update app",
		Description: "Update a web app (admin only)",
		OperationID: "admin.update_app",
		Tags:        []string{"Admin"},
	})

	fiberoapi.Delete(adminCtrl.FiberOapi, "/apps/:id", adminCtrl.DeleteApp, fiberoapi.OpenAPIOptions{
		Summary:     "Delete app",
		Description: "Delete a web app (admin only)",
		OperationID: "admin.delete_app",
		Tags:        []string{"Admin"},
	})

	// User management
	fiberoapi.Get(adminCtrl.FiberOapi, "/users", adminCtrl.GetUsers, fiberoapi.OpenAPIOptions{
		Summary:     "Get all users",
		Description: "Get all users (admin only)",
		OperationID: "admin.get_users",
		Tags:        []string{"Admin"},
	})

	fiberoapi.Put(adminCtrl.FiberOapi, "/users/:id", adminCtrl.UpdateUser, fiberoapi.OpenAPIOptions{
		Summary:     "Update user",
		Description: "Update user role or active status (admin only)",
		OperationID: "admin.update_user",
		Tags:        []string{"Admin"},
	})

	// Permission management
	fiberoapi.Post(adminCtrl.FiberOapi, "/permissions/hosts", adminCtrl.GrantHostPermission, fiberoapi.OpenAPIOptions{
		Summary:     "Grant host permission",
		Description: "Grant a user permission to access a host (admin only)",
		OperationID: "admin.grant_host_permission",
		Tags:        []string{"Admin"},
	})

	fiberoapi.Delete(adminCtrl.FiberOapi, "/permissions/hosts", adminCtrl.RevokeHostPermission, fiberoapi.OpenAPIOptions{
		Summary:     "Revoke host permission",
		Description: "Revoke a user's permission to access a host (admin only)",
		OperationID: "admin.revoke_host_permission",
		Tags:        []string{"Admin"},
	})

	fiberoapi.Post(adminCtrl.FiberOapi, "/permissions/apps", adminCtrl.GrantAppPermission, fiberoapi.OpenAPIOptions{
		Summary:     "Grant app permission",
		Description: "Grant a user permission to access an app (admin only)",
		OperationID: "admin.grant_app_permission",
		Tags:        []string{"Admin"},
	})

	fiberoapi.Delete(adminCtrl.FiberOapi, "/permissions/apps", adminCtrl.RevokeAppPermission, fiberoapi.OpenAPIOptions{
		Summary:     "Revoke app permission",
		Description: "Revoke a user's permission to access an app (admin only)",
		OperationID: "admin.revoke_app_permission",
		Tags:        []string{"Admin"},
	})

	fiberoapi.Post(adminCtrl.FiberOapi, "/permissions/apps/groups", adminCtrl.GrantGroupAppPermission, fiberoapi.OpenAPIOptions{
		Summary:     "Grant group app permission",
		Description: "Grant a group permission to access an app (admin only)",
		OperationID: "admin.grant_group_app_permission",
		Tags:        []string{"Admin"},
	})

	fiberoapi.Delete(adminCtrl.FiberOapi, "/permissions/apps/groups", adminCtrl.RevokeGroupAppPermission, fiberoapi.OpenAPIOptions{
		Summary:     "Revoke group app permission",
		Description: "Revoke a group's permission to access an app (admin only)",
		OperationID: "admin.revoke_group_app_permission",
		Tags:        []string{"Admin"},
	})
}

