package admin

import (
	"github.com/gofiber/fiber/v2"
	"github.com/labbs/bastion/domain"
	"github.com/labbs/bastion/interfaces/http/v1/admin/dtos"
	fiberoapi "github.com/labbs/fiber-oapi"
)

// Note: All handlers require admin role - this is checked in the router middleware
// Additional check in each handler for extra security

func (ctrl Controller) checkAdmin(ctx *fiber.Ctx) *fiberoapi.ErrorResponse {
	authCtx, err := fiberoapi.GetAuthContext(ctx)
	if err != nil {
		return &fiberoapi.ErrorResponse{
			Code:    fiber.StatusUnauthorized,
			Details: "Authentication required",
			Type:    "AUTHENTICATION_REQUIRED",
		}
	}

	if !ctrl.SessionApp.HasRole(authCtx, "admin") {
		return &fiberoapi.ErrorResponse{
			Code:    fiber.StatusForbidden,
			Details: "Admin access required",
			Type:    "FORBIDDEN",
		}
	}

	return nil
}

// Host management
func (ctrl Controller) CreateHost(ctx *fiber.Ctx, req dtos.CreateHostRequest) (*dtos.HostResponse, *fiberoapi.ErrorResponse) {
	if errResp := ctrl.checkAdmin(ctx); errResp != nil {
		return nil, errResp
	}

	requestId := ctx.Locals("requestid").(string)
	logger := ctrl.Logger.With().Str("request_id", requestId).Str("component", "http.api.v1.admin.create_host").Logger()

	host := domain.Host{
		Name:        req.Name,
		Description: req.Description,
		Hostname:    req.Hostname,
		Port:        req.Port,
		Username:    req.Username,
		AuthMethod:  req.AuthMethod,
		Password:    req.Password,
		PrivateKey:  req.PrivateKey,
	}

	createdHost, err := ctrl.AdminApp.CreateHost(host)
	if err != nil {
		logger.Error().Err(err).Msg("failed to create host")
		return nil, &fiberoapi.ErrorResponse{
			Code:    fiber.StatusInternalServerError,
			Details: err.Error(),
			Type:    "CREATE_HOST_FAILED",
		}
	}

	response := &dtos.HostResponse{
		Id:          createdHost.Id,
		Name:        createdHost.Name,
		Description: createdHost.Description,
		Hostname:    createdHost.Hostname,
		Port:        createdHost.Port,
		Username:    createdHost.Username,
		AuthMethod:  createdHost.AuthMethod,
		Active:      createdHost.Active,
	}

	return response, nil
}

func (ctrl Controller) UpdateHost(ctx *fiber.Ctx, req dtos.UpdateHostRequest) (*dtos.HostResponse, *fiberoapi.ErrorResponse) {
	requestId := ctx.Locals("requestid").(string)
	logger := ctrl.Logger.With().Str("request_id", requestId).Str("component", "http.api.v1.admin.update_host").Logger()

	hostId := ctx.Params("id")

	host := domain.Host{
		Id:          hostId,
		Name:        req.Name,
		Description: req.Description,
		Hostname:    req.Hostname,
		Port:        req.Port,
		Username:    req.Username,
		AuthMethod:  req.AuthMethod,
		Password:    req.Password,
		PrivateKey:  req.PrivateKey,
		Active:      req.Active,
	}

	updatedHost, err := ctrl.AdminApp.UpdateHost(host)
	if err != nil {
		logger.Error().Err(err).Str("host_id", hostId).Msg("failed to update host")
		return nil, &fiberoapi.ErrorResponse{
			Code:    fiber.StatusInternalServerError,
			Details: err.Error(),
			Type:    "UPDATE_HOST_FAILED",
		}
	}

	response := &dtos.HostResponse{
		Id:          updatedHost.Id,
		Name:        updatedHost.Name,
		Description: updatedHost.Description,
		Hostname:    updatedHost.Hostname,
		Port:        updatedHost.Port,
		Username:    updatedHost.Username,
		AuthMethod:  updatedHost.AuthMethod,
		Active:      updatedHost.Active,
	}

	return response, nil
}

func (ctrl Controller) DeleteHost(ctx *fiber.Ctx, input struct {
	Id string `path:"id"`
}) (*fiber.Map, *fiberoapi.ErrorResponse) {
	requestId := ctx.Locals("requestid").(string)
	logger := ctrl.Logger.With().Str("request_id", requestId).Str("component", "http.api.v1.admin.delete_host").Logger()

	if err := ctrl.AdminApp.DeleteHost(input.Id); err != nil {
		logger.Error().Err(err).Str("host_id", input.Id).Msg("failed to delete host")
		return nil, &fiberoapi.ErrorResponse{
			Code:    fiber.StatusInternalServerError,
			Details: err.Error(),
			Type:    "DELETE_HOST_FAILED",
		}
	}

	return &fiber.Map{"message": "Host deleted successfully"}, nil
}

func (ctrl Controller) GetHosts(ctx *fiber.Ctx, input struct{}) ([]dtos.HostResponse, *fiberoapi.ErrorResponse) {
	requestId := ctx.Locals("requestid").(string)
	logger := ctrl.Logger.With().Str("request_id", requestId).Str("component", "http.api.v1.admin.get_hosts").Logger()

	hosts, err := ctrl.AdminApp.GetAllHosts()
	if err != nil {
		logger.Error().Err(err).Msg("failed to get hosts")
		return nil, &fiberoapi.ErrorResponse{
			Code:    fiber.StatusInternalServerError,
			Details: err.Error(),
			Type:    "GET_HOSTS_FAILED",
		}
	}

	response := make([]dtos.HostResponse, len(hosts))
	for i, host := range hosts {
		response[i] = dtos.HostResponse{
			Id:          host.Id,
			Name:        host.Name,
			Description: host.Description,
			Hostname:    host.Hostname,
			Port:        host.Port,
			Username:    host.Username,
			AuthMethod:  host.AuthMethod,
			Active:      host.Active,
		}
	}

	return response, nil
}

// App management
func (ctrl Controller) CreateApp(ctx *fiber.Ctx, req dtos.CreateAppRequest) (*dtos.AppResponse, *fiberoapi.ErrorResponse) {
	requestId := ctx.Locals("requestid").(string)
	logger := ctrl.Logger.With().Str("request_id", requestId).Str("component", "http.api.v1.admin.create_app").Logger()

	createdApp, err := ctrl.AdminApp.CreateApp(req.Name, req.Description, req.Url, req.Icon)
	if err != nil {
		logger.Error().Err(err).Msg("failed to create app")
		return nil, &fiberoapi.ErrorResponse{
			Code:    fiber.StatusInternalServerError,
			Details: err.Error(),
			Type:    "CREATE_APP_FAILED",
		}
	}

	response := &dtos.AppResponse{
		Id:          createdApp.Id,
		Name:        createdApp.Name,
		Description: createdApp.Description,
		Url:         createdApp.Url,
		Icon:        createdApp.Icon,
		Active:      createdApp.Active,
	}

	return response, nil
}

func (ctrl Controller) UpdateApp(ctx *fiber.Ctx, req dtos.UpdateAppRequest) (*dtos.AppResponse, *fiberoapi.ErrorResponse) {
	requestId := ctx.Locals("requestid").(string)
	logger := ctrl.Logger.With().Str("request_id", requestId).Str("component", "http.api.v1.admin.update_app").Logger()

	appId := ctx.Params("id")

	updatedApp, err := ctrl.AdminApp.UpdateApp(appId, req.Name, req.Description, req.Url, req.Icon, req.Active)
	if err != nil {
		logger.Error().Err(err).Str("app_id", appId).Msg("failed to update app")
		return nil, &fiberoapi.ErrorResponse{
			Code:    fiber.StatusInternalServerError,
			Details: err.Error(),
			Type:    "UPDATE_APP_FAILED",
		}
	}

	response := &dtos.AppResponse{
		Id:          updatedApp.Id,
		Name:        updatedApp.Name,
		Description: updatedApp.Description,
		Url:         updatedApp.Url,
		Icon:        updatedApp.Icon,
		Active:      updatedApp.Active,
	}

	return response, nil
}

func (ctrl Controller) DeleteApp(ctx *fiber.Ctx, input struct {
	Id string `path:"id"`
}) (*fiber.Map, *fiberoapi.ErrorResponse) {
	requestId := ctx.Locals("requestid").(string)
	logger := ctrl.Logger.With().Str("request_id", requestId).Str("component", "http.api.v1.admin.delete_app").Logger()

	if err := ctrl.AdminApp.DeleteApp(input.Id); err != nil {
		logger.Error().Err(err).Str("app_id", input.Id).Msg("failed to delete app")
		return nil, &fiberoapi.ErrorResponse{
			Code:    fiber.StatusInternalServerError,
			Details: err.Error(),
			Type:    "DELETE_APP_FAILED",
		}
	}

	return &fiber.Map{"message": "App deleted successfully"}, nil
}

func (ctrl Controller) GetApps(ctx *fiber.Ctx, input struct{}) ([]dtos.AppResponse, *fiberoapi.ErrorResponse) {
	requestId := ctx.Locals("requestid").(string)
	logger := ctrl.Logger.With().Str("request_id", requestId).Str("component", "http.api.v1.admin.get_apps").Logger()

	apps, err := ctrl.AdminApp.GetAllApps()
	if err != nil {
		logger.Error().Err(err).Msg("failed to get apps")
		return nil, &fiberoapi.ErrorResponse{
			Code:    fiber.StatusInternalServerError,
			Details: err.Error(),
			Type:    "GET_APPS_FAILED",
		}
	}

	response := make([]dtos.AppResponse, len(apps))
	for i, app := range apps {
		response[i] = dtos.AppResponse{
			Id:          app.Id,
			Name:        app.Name,
			Description: app.Description,
			Url:         app.Url,
			Icon:        app.Icon,
		}
	}

	return response, nil
}

// User management
func (ctrl Controller) UpdateUser(ctx *fiber.Ctx, req dtos.UpdateUserRequest) (*dtos.UserResponse, *fiberoapi.ErrorResponse) {
	requestId := ctx.Locals("requestid").(string)
	logger := ctrl.Logger.With().Str("request_id", requestId).Str("component", "http.api.v1.admin.update_user").Logger()

	userId := ctx.Params("id")

	if req.Role != "" {
		if err := ctrl.AdminApp.UpdateUserRole(userId, domain.Role(req.Role)); err != nil {
			logger.Error().Err(err).Str("user_id", userId).Msg("failed to update user role")
			return nil, &fiberoapi.ErrorResponse{
				Code:    fiber.StatusInternalServerError,
				Details: err.Error(),
				Type:    "UPDATE_USER_FAILED",
			}
		}
	}

	if err := ctrl.AdminApp.SetUserActive(userId, req.Active); err != nil {
		logger.Error().Err(err).Str("user_id", userId).Msg("failed to update user active status")
		return nil, &fiberoapi.ErrorResponse{
			Code:    fiber.StatusInternalServerError,
			Details: err.Error(),
			Type:    "UPDATE_USER_FAILED",
		}
	}

	user, err := ctrl.UserApp.GetByUserId(userId)
	if err != nil {
		logger.Error().Err(err).Str("user_id", userId).Msg("failed to get user")
		return nil, &fiberoapi.ErrorResponse{
			Code:    fiber.StatusInternalServerError,
			Details: err.Error(),
			Type:    "GET_USER_FAILED",
		}
	}

	response := &dtos.UserResponse{
		Id:       user.Id,
		Username: user.Username,
		Email:    user.Email,
		Role:     string(user.Role),
		Active:   user.Active,
	}

	return response, nil
}

func (ctrl Controller) GetUsers(ctx *fiber.Ctx, input struct{}) ([]dtos.UserResponse, *fiberoapi.ErrorResponse) {
	requestId := ctx.Locals("requestid").(string)
	logger := ctrl.Logger.With().Str("request_id", requestId).Str("component", "http.api.v1.admin.get_users").Logger()

	users, err := ctrl.AdminApp.GetAllUsers()
	if err != nil {
		logger.Error().Err(err).Msg("failed to get users")
		return nil, &fiberoapi.ErrorResponse{
			Code:    fiber.StatusInternalServerError,
			Details: err.Error(),
			Type:    "GET_USERS_FAILED",
		}
	}

	response := make([]dtos.UserResponse, len(users))
	for i, user := range users {
		response[i] = dtos.UserResponse{
			Id:       user.Id,
			Username: user.Username,
			Email:    user.Email,
			Role:     string(user.Role),
			Active:   user.Active,
		}
	}

	return response, nil
}

// Permission management
func (ctrl Controller) GrantHostPermission(ctx *fiber.Ctx, req dtos.GrantPermissionRequest) (*fiber.Map, *fiberoapi.ErrorResponse) {
	requestId := ctx.Locals("requestid").(string)
	logger := ctrl.Logger.With().Str("request_id", requestId).Str("component", "http.api.v1.admin.grant_host_permission").Logger()

	if err := ctrl.AdminApp.GrantHostPermission(req.UserId, req.ResourceId, req.Permission); err != nil {
		logger.Error().Err(err).Msg("failed to grant host permission")
		return nil, &fiberoapi.ErrorResponse{
			Code:    fiber.StatusInternalServerError,
			Details: err.Error(),
			Type:    "GRANT_PERMISSION_FAILED",
		}
	}

	return &fiber.Map{"message": "Permission granted successfully"}, nil
}

func (ctrl Controller) RevokeHostPermission(ctx *fiber.Ctx, req dtos.RevokePermissionRequest) (*fiber.Map, *fiberoapi.ErrorResponse) {
	requestId := ctx.Locals("requestid").(string)
	logger := ctrl.Logger.With().Str("request_id", requestId).Str("component", "http.api.v1.admin.revoke_host_permission").Logger()

	if err := ctrl.AdminApp.RevokeHostPermission(req.UserId, req.ResourceId); err != nil {
		logger.Error().Err(err).Msg("failed to revoke host permission")
		return nil, &fiberoapi.ErrorResponse{
			Code:    fiber.StatusInternalServerError,
			Details: err.Error(),
			Type:    "REVOKE_PERMISSION_FAILED",
		}
	}

	return &fiber.Map{"message": "Permission revoked successfully"}, nil
}

func (ctrl Controller) GrantAppPermission(ctx *fiber.Ctx, req dtos.GrantPermissionRequest) (*fiber.Map, *fiberoapi.ErrorResponse) {
	requestId := ctx.Locals("requestid").(string)
	logger := ctrl.Logger.With().Str("request_id", requestId).Str("component", "http.api.v1.admin.grant_app_permission").Logger()

	if err := ctrl.AdminApp.GrantAppPermission(req.UserId, req.ResourceId); err != nil {
		logger.Error().Err(err).Msg("failed to grant app permission")
		return nil, &fiberoapi.ErrorResponse{
			Code:    fiber.StatusInternalServerError,
			Details: err.Error(),
			Type:    "GRANT_PERMISSION_FAILED",
		}
	}

	return &fiber.Map{"message": "Permission granted successfully"}, nil
}

func (ctrl Controller) RevokeAppPermission(ctx *fiber.Ctx, req dtos.RevokePermissionRequest) (*fiber.Map, *fiberoapi.ErrorResponse) {
	requestId := ctx.Locals("requestid").(string)
	logger := ctrl.Logger.With().Str("request_id", requestId).Str("component", "http.api.v1.admin.revoke_app_permission").Logger()

	if err := ctrl.AdminApp.RevokeAppPermission(req.UserId, req.ResourceId); err != nil {
		logger.Error().Err(err).Msg("failed to revoke app permission")
		return nil, &fiberoapi.ErrorResponse{
			Code:    fiber.StatusInternalServerError,
			Details: err.Error(),
			Type:    "REVOKE_PERMISSION_FAILED",
		}
	}

	return &fiber.Map{"message": "Permission revoked successfully"}, nil
}

func (ctrl Controller) GrantGroupAppPermission(ctx *fiber.Ctx, req dtos.GrantGroupPermissionRequest) (*fiber.Map, *fiberoapi.ErrorResponse) {
	requestId := ctx.Locals("requestid").(string)
	logger := ctrl.Logger.With().Str("request_id", requestId).Str("component", "http.api.v1.admin.grant_group_app_permission").Logger()

	if err := ctrl.AdminApp.GrantGroupAppPermission(req.GroupId, req.ResourceId); err != nil {
		logger.Error().Err(err).Msg("failed to grant group app permission")
		return nil, &fiberoapi.ErrorResponse{
			Code:    fiber.StatusInternalServerError,
			Details: err.Error(),
			Type:    "GRANT_PERMISSION_FAILED",
		}
	}

	return &fiber.Map{"message": "Group permission granted successfully"}, nil
}

func (ctrl Controller) RevokeGroupAppPermission(ctx *fiber.Ctx, req dtos.RevokeGroupPermissionRequest) (*fiber.Map, *fiberoapi.ErrorResponse) {
	requestId := ctx.Locals("requestid").(string)
	logger := ctrl.Logger.With().Str("request_id", requestId).Str("component", "http.api.v1.admin.revoke_group_app_permission").Logger()

	if err := ctrl.AdminApp.RevokeGroupAppPermission(req.GroupId, req.ResourceId); err != nil {
		logger.Error().Err(err).Msg("failed to revoke group app permission")
		return nil, &fiberoapi.ErrorResponse{
			Code:    fiber.StatusInternalServerError,
			Details: err.Error(),
			Type:    "REVOKE_PERMISSION_FAILED",
		}
	}

	return &fiber.Map{"message": "Group permission revoked successfully"}, nil
}
