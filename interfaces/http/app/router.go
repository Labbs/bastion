package app

import (
	"github.com/gofiber/fiber/v2"
	"github.com/labbs/bastion/application"
	"github.com/labbs/bastion/domain"
	"github.com/labbs/bastion/infrastructure"
	"github.com/labbs/bastion/infrastructure/config"
	"github.com/rs/zerolog"
)

type Controller struct {
	Config     config.Config
	Logger     zerolog.Logger
	Fiber      *fiber.App
	SessionApp *application.SessionApp
	AdminApp   *application.AdminApp
}

// authMiddleware vérifie que l'utilisateur est authentifié
// Il vérifie le token dans le header Authorization ou dans un cookie
func authMiddleware(sessionApp *application.SessionApp, logger zerolog.Logger) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		var token string

		// Vérifier d'abord le header Authorization
		authHeader := ctx.Get("Authorization")
		if authHeader != "" && len(authHeader) > 7 && authHeader[:7] == "Bearer " {
			token = authHeader[7:]
		}

		// Si pas de token dans le header, vérifier le cookie
		if token == "" {
			token = ctx.Cookies("token")
		}

		// Si toujours pas de token, rediriger vers login
		if token == "" {
			logger.Debug().Msg("no authentication token found for apps page")
			return ctx.Redirect("/login")
		}

		// Valider le token directement avec SessionApp
		authCtx, err := sessionApp.ValidateToken(token)
		if err != nil {
			logger.Debug().Err(err).Msg("invalid token")
			// Supprimer le cookie invalide
			ctx.ClearCookie("token")
			return ctx.Redirect("/login")
		}

		// Vérifier que l'utilisateur existe et est actif
		user, err := sessionApp.UserApp.GetByUserId(authCtx.UserID)
		if err != nil || !user.Active {
			logger.Debug().Str("user_id", authCtx.UserID).Msg("user not found or inactive")
			ctx.ClearCookie("token")
			return ctx.Redirect("/login")
		}

		return ctx.Next()
	}
}

// adminMiddleware vérifie que l'utilisateur est authentifié ET est admin
func adminMiddleware(sessionApp *application.SessionApp, logger zerolog.Logger) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		var token string

		// Vérifier d'abord le header Authorization
		authHeader := ctx.Get("Authorization")
		if authHeader != "" && len(authHeader) > 7 && authHeader[:7] == "Bearer " {
			token = authHeader[7:]
		}

		// Si pas de token dans le header, vérifier le cookie
		if token == "" {
			token = ctx.Cookies("token")
		}

		// Si toujours pas de token, rediriger vers login
		if token == "" {
			logger.Debug().Msg("no authentication token found for admin page")
			return ctx.Redirect("/login")
		}

		// Valider le token directement avec SessionApp
		authCtx, err := sessionApp.ValidateToken(token)
		if err != nil {
			logger.Debug().Err(err).Msg("invalid token")
			ctx.ClearCookie("token")
			return ctx.Redirect("/login")
		}

		// Vérifier que l'utilisateur existe et est actif
		user, err := sessionApp.UserApp.GetByUserId(authCtx.UserID)
		if err != nil || !user.Active {
			logger.Debug().Str("user_id", authCtx.UserID).Msg("user not found or inactive")
			ctx.ClearCookie("token")
			return ctx.Redirect("/login")
		}

		// Vérifier que l'utilisateur est admin
		if !sessionApp.HasRole(authCtx, "admin") {
			logger.Debug().Str("user_id", authCtx.UserID).Msg("non-admin user attempted to access admin page")
			return ctx.Redirect("/apps")
		}

		return ctx.Next()
	}
}

func SetupAppRouter(deps infrastructure.Deps) {
	deps.Logger.Info().Str("component", "http.router.app").Msg("Setting up app routes")

	controller := Controller{
		Config:     deps.Config,
		Logger:     deps.Logger,
		Fiber:      deps.Http.Fiber,
		SessionApp: deps.SessionApp,
		AdminApp:   deps.AdminApp,
	}

	controller.Fiber.Get("/", func(ctx *fiber.Ctx) error {
		return ctx.Render("templates/index", fiber.Map{
			"Title": "Bastion",
		})
	})

	controller.Fiber.Get("/login", func(ctx *fiber.Ctx) error {
		return ctx.Render("templates/login", fiber.Map{})
	})

	// Route protégée : nécessite une authentification
	controller.Fiber.Get("/apps", authMiddleware(deps.SessionApp, deps.Logger), func(ctx *fiber.Ctx) error {
		return ctx.Render("templates/apps", fiber.Map{})
	})

	// Route admin : nécessite une authentification et le rôle admin
	controller.Fiber.Get("/admin", adminMiddleware(deps.SessionApp, deps.Logger), func(ctx *fiber.Ctx) error {
		// Récupérer les données pour toutes les sections
		apps, err := deps.AdminApp.GetAllApps()
		if err != nil {
			deps.Logger.Error().Err(err).Msg("failed to get apps for admin page")
			apps = []domain.WebApp{}
		}

		users, err := deps.AdminApp.GetAllUsers()
		if err != nil {
			deps.Logger.Error().Err(err).Msg("failed to get users for admin page")
			users = []domain.User{}
		}

		groups, err := deps.AdminApp.GetAllGroups()
		if err != nil {
			deps.Logger.Error().Err(err).Msg("failed to get groups for admin page")
			groups = []domain.Group{}
		}

		// Get current user ID for group creation
		token := ctx.Cookies("token")
		if token == "" {
			authHeader := ctx.Get("Authorization")
			if authHeader != "" && len(authHeader) > 7 && authHeader[:7] == "Bearer " {
				token = authHeader[7:]
			}
		}
		var currentUserId string
		if token != "" {
			authCtx, err := deps.SessionApp.ValidateToken(token)
			if err == nil {
				currentUserId = authCtx.UserID
			}
		}

		return ctx.Render("templates/admin", fiber.Map{
			"Apps":          apps,
			"Users":         users,
			"Groups":        groups,
			"CurrentUserId": currentUserId,
			"Error":         ctx.Query("error"),
			"Success":       ctx.Query("success"),
		})
	})

	// Route pour créer une app
	controller.Fiber.Post("/admin/apps", adminMiddleware(deps.SessionApp, deps.Logger), func(ctx *fiber.Ctx) error {
		name := ctx.FormValue("name")
		description := ctx.FormValue("description")
		url := ctx.FormValue("url")
		icon := ctx.FormValue("icon")

		_, err := deps.AdminApp.CreateApp(name, description, url, icon)
		if err != nil {
			deps.Logger.Error().Err(err).Msg("failed to create app")
			return ctx.Redirect("/admin?error=create_failed")
		}

		return ctx.Redirect("/admin?success=created")
	})

	// Route pour modifier une app
	controller.Fiber.Post("/admin/apps/:id", adminMiddleware(deps.SessionApp, deps.Logger), func(ctx *fiber.Ctx) error {
		appId := ctx.Params("id")
		name := ctx.FormValue("name")
		description := ctx.FormValue("description")
		url := ctx.FormValue("url")
		icon := ctx.FormValue("icon")
		active := ctx.FormValue("active") == "on" || ctx.FormValue("active") == "true"

		_, err := deps.AdminApp.UpdateApp(appId, name, description, url, icon, active)
		if err != nil {
			deps.Logger.Error().Err(err).Str("app_id", appId).Msg("failed to update app")
			return ctx.Redirect("/admin?error=update_failed")
		}

		return ctx.Redirect("/admin?success=updated")
	})

	// Route pour supprimer une app
	controller.Fiber.Post("/admin/apps/:id/delete", adminMiddleware(deps.SessionApp, deps.Logger), func(ctx *fiber.Ctx) error {
		appId := ctx.Params("id")

		err := deps.AdminApp.DeleteApp(appId)
		if err != nil {
			deps.Logger.Error().Err(err).Str("app_id", appId).Msg("failed to delete app")
			return ctx.Redirect("/admin?error=delete_failed")
		}

		return ctx.Redirect("/admin?success=deleted")
	})

	// Route pour éditer une app (page d'édition)
	controller.Fiber.Get("/admin/apps/:id/edit", adminMiddleware(deps.SessionApp, deps.Logger), func(ctx *fiber.Ctx) error {
		appId := ctx.Params("id")
		app, err := deps.AdminApp.GetAppById(appId)
		if err != nil {
			deps.Logger.Error().Err(err).Str("app_id", appId).Msg("failed to get app for edit")
			return ctx.Redirect("/admin?error=app_not_found")
		}

		return ctx.Render("templates/admin_edit", fiber.Map{
			"App": app,
		})
	})

	// ===== USER MANAGEMENT ROUTES =====
	controller.Fiber.Get("/admin/users/new", adminMiddleware(deps.SessionApp, deps.Logger), func(ctx *fiber.Ctx) error {
		return ctx.Render("templates/admin_user_new", fiber.Map{})
	})

	controller.Fiber.Post("/admin/users", adminMiddleware(deps.SessionApp, deps.Logger), func(ctx *fiber.Ctx) error {
		username := ctx.FormValue("username")
		email := ctx.FormValue("email")
		password := ctx.FormValue("password")
		role := ctx.FormValue("role")

		_, err := deps.AdminApp.CreateUser(username, email, password, domain.Role(role))
		if err != nil {
			deps.Logger.Error().Err(err).Msg("failed to create user")
			return ctx.Redirect("/admin?error=user_create_failed")
		}

		return ctx.Redirect("/admin?success=user_created")
	})

	controller.Fiber.Get("/admin/users/:id/edit", adminMiddleware(deps.SessionApp, deps.Logger), func(ctx *fiber.Ctx) error {
		userId := ctx.Params("id")
		user, err := deps.AdminApp.GetUserById(userId)
		if err != nil {
			return ctx.Redirect("/admin?error=user_not_found")
		}
		return ctx.Render("templates/admin_user_edit", fiber.Map{"User": user})
	})

	controller.Fiber.Post("/admin/users/:id", adminMiddleware(deps.SessionApp, deps.Logger), func(ctx *fiber.Ctx) error {
		userId := ctx.Params("id")
		username := ctx.FormValue("username")
		email := ctx.FormValue("email")
		role := ctx.FormValue("role")
		active := ctx.FormValue("active") == "on"

		err := deps.AdminApp.UpdateUser(userId, username, email, domain.Role(role), active)
		if err != nil {
			return ctx.Redirect("/admin?error=user_update_failed")
		}

		return ctx.Redirect("/admin?success=user_updated")
	})

	controller.Fiber.Post("/admin/users/:id/delete", adminMiddleware(deps.SessionApp, deps.Logger), func(ctx *fiber.Ctx) error {
		userId := ctx.Params("id")
		err := deps.AdminApp.DeleteUser(userId)
		if err != nil {
			return ctx.Redirect("/admin?error=user_delete_failed")
		}
		return ctx.Redirect("/admin?success=user_deleted")
	})

	// ===== GROUP MANAGEMENT ROUTES =====
	controller.Fiber.Get("/admin/groups/new", adminMiddleware(deps.SessionApp, deps.Logger), func(ctx *fiber.Ctx) error {
		token := ctx.Cookies("token")
		if token == "" {
			authHeader := ctx.Get("Authorization")
			if authHeader != "" && len(authHeader) > 7 && authHeader[:7] == "Bearer " {
				token = authHeader[7:]
			}
		}
		var currentUserId string
		if token != "" {
			authCtx, err := deps.SessionApp.ValidateToken(token)
			if err == nil {
				currentUserId = authCtx.UserID
			}
		}
		users, _ := deps.AdminApp.GetAllUsers()
		return ctx.Render("templates/admin_group_new", fiber.Map{
			"CurrentUserId": currentUserId,
			"Users":         users,
		})
	})

	controller.Fiber.Post("/admin/groups", adminMiddleware(deps.SessionApp, deps.Logger), func(ctx *fiber.Ctx) error {
		name := ctx.FormValue("name")
		description := ctx.FormValue("description")
		role := ctx.FormValue("role")
		ownerId := ctx.FormValue("owner_id")

		_, err := deps.AdminApp.CreateGroup(name, description, ownerId, domain.Role(role))
		if err != nil {
			return ctx.Redirect("/admin?error=group_create_failed")
		}

		return ctx.Redirect("/admin?success=group_created")
	})

	controller.Fiber.Get("/admin/groups/:id/edit", adminMiddleware(deps.SessionApp, deps.Logger), func(ctx *fiber.Ctx) error {
		groupId := ctx.Params("id")
		group, err := deps.AdminApp.GetGroupById(groupId)
		if err != nil {
			return ctx.Redirect("/admin?error=group_not_found")
		}
		return ctx.Render("templates/admin_group_edit", fiber.Map{"Group": group})
	})

	controller.Fiber.Post("/admin/groups/:id", adminMiddleware(deps.SessionApp, deps.Logger), func(ctx *fiber.Ctx) error {
		groupId := ctx.Params("id")
		name := ctx.FormValue("name")
		description := ctx.FormValue("description")
		role := ctx.FormValue("role")

		_, err := deps.AdminApp.UpdateGroup(groupId, name, description, domain.Role(role))
		if err != nil {
			return ctx.Redirect("/admin?error=group_update_failed")
		}

		return ctx.Redirect("/admin?success=group_updated")
	})

	controller.Fiber.Post("/admin/groups/:id/delete", adminMiddleware(deps.SessionApp, deps.Logger), func(ctx *fiber.Ctx) error {
		groupId := ctx.Params("id")
		err := deps.AdminApp.DeleteGroup(groupId)
		if err != nil {
			return ctx.Redirect("/admin?error=group_delete_failed")
		}
		return ctx.Redirect("/admin?success=group_deleted")
	})

	controller.Fiber.Get("/admin/groups/:id/members", adminMiddleware(deps.SessionApp, deps.Logger), func(ctx *fiber.Ctx) error {
		groupId := ctx.Params("id")
		group, err := deps.AdminApp.GetGroupById(groupId)
		if err != nil {
			return ctx.Redirect("/admin?error=group_not_found")
		}
		members, err := deps.AdminApp.GetGroupMembers(groupId)
		if err != nil {
			members = []domain.User{}
		}
		allUsers, _ := deps.AdminApp.GetAllUsers()
		return ctx.Render("templates/admin_group_members", fiber.Map{
			"Group":    group,
			"Members":  members,
			"AllUsers": allUsers,
		})
	})

	controller.Fiber.Post("/admin/groups/:id/members", adminMiddleware(deps.SessionApp, deps.Logger), func(ctx *fiber.Ctx) error {
		groupId := ctx.Params("id")
		userId := ctx.FormValue("user_id")
		err := deps.AdminApp.AddUserToGroup(groupId, userId)
		if err != nil {
			return ctx.Redirect("/admin/groups/" + groupId + "/members?error=add_member_failed")
		}
		return ctx.Redirect("/admin/groups/" + groupId + "/members?success=member_added")
	})

	controller.Fiber.Post("/admin/groups/:id/members/:userId/remove", adminMiddleware(deps.SessionApp, deps.Logger), func(ctx *fiber.Ctx) error {
		groupId := ctx.Params("id")
		userId := ctx.Params("userId")
		err := deps.AdminApp.RemoveUserFromGroup(groupId, userId)
		if err != nil {
			return ctx.Redirect("/admin/groups/" + groupId + "/members?error=remove_member_failed")
		}
		return ctx.Redirect("/admin/groups/" + groupId + "/members?success=member_removed")
	})

	// ===== APP PERMISSIONS ROUTES =====
	controller.Fiber.Get("/admin/apps/:id/permissions", adminMiddleware(deps.SessionApp, deps.Logger), func(ctx *fiber.Ctx) error {
		appId := ctx.Params("id")
		app, err := deps.AdminApp.GetAppById(appId)
		if err != nil {
			return ctx.Redirect("/admin?error=app_not_found")
		}

		users, _ := deps.AdminApp.GetAllUsers()
		groups, _ := deps.AdminApp.GetAllGroups()

		// Get existing permissions
		userPerms, err := deps.AdminApp.AppPermissionPers.GetAppUserPermissions(appId)
		if err != nil {
			deps.Logger.Error().Err(err).Msg("failed to get user permissions")
			userPerms = []domain.UserAppPermission{}
		}
		groupPerms, err := deps.AdminApp.AppPermissionPers.GetAppGroupPermissions(appId)
		if err != nil {
			deps.Logger.Error().Err(err).Msg("failed to get group permissions")
			groupPerms = []domain.GroupAppPermission{}
		}

		return ctx.Render("templates/admin_app_permissions", fiber.Map{
			"App":        app,
			"Users":      users,
			"Groups":     groups,
			"UserPerms":  userPerms,
			"GroupPerms": groupPerms,
		})
	})

	controller.Fiber.Post("/admin/apps/:id/permissions/user", adminMiddleware(deps.SessionApp, deps.Logger), func(ctx *fiber.Ctx) error {
		appId := ctx.Params("id")
		userId := ctx.FormValue("user_id")

		err := deps.AdminApp.GrantAppPermission(userId, appId)
		if err != nil {
			return ctx.Redirect("/admin/apps/" + appId + "/permissions?error=permission_grant_failed")
		}
		return ctx.Redirect("/admin/apps/" + appId + "/permissions?success=permission_granted")
	})

	controller.Fiber.Post("/admin/apps/:id/permissions/user/:userId/revoke", adminMiddleware(deps.SessionApp, deps.Logger), func(ctx *fiber.Ctx) error {
		appId := ctx.Params("id")
		userId := ctx.Params("userId")

		err := deps.AdminApp.RevokeAppPermission(userId, appId)
		if err != nil {
			return ctx.Redirect("/admin/apps/" + appId + "/permissions?error=permission_revoke_failed")
		}
		return ctx.Redirect("/admin/apps/" + appId + "/permissions?success=permission_revoked")
	})

	controller.Fiber.Post("/admin/apps/:id/permissions/group", adminMiddleware(deps.SessionApp, deps.Logger), func(ctx *fiber.Ctx) error {
		appId := ctx.Params("id")
		groupId := ctx.FormValue("group_id")

		err := deps.AdminApp.GrantGroupAppPermission(groupId, appId)
		if err != nil {
			return ctx.Redirect("/admin/apps/" + appId + "/permissions?error=permission_grant_failed")
		}
		return ctx.Redirect("/admin/apps/" + appId + "/permissions?success=permission_granted")
	})

	controller.Fiber.Post("/admin/apps/:id/permissions/group/:groupId/revoke", adminMiddleware(deps.SessionApp, deps.Logger), func(ctx *fiber.Ctx) error {
		appId := ctx.Params("id")
		groupId := ctx.Params("groupId")

		err := deps.AdminApp.RevokeGroupAppPermission(groupId, appId)
		if err != nil {
			return ctx.Redirect("/admin/apps/" + appId + "/permissions?error=permission_revoke_failed")
		}
		return ctx.Redirect("/admin/apps/" + appId + "/permissions?success=permission_revoked")
	})

	// Setup proxy routes
	SetupProxyRouter(deps)
}
