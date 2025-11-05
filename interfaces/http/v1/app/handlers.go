package app

import (
	"github.com/gofiber/fiber/v2"
	"github.com/labbs/bastion/interfaces/http/v1/app/dtos"
	fiberoapi "github.com/labbs/fiber-oapi"
)

func (ctrl Controller) GetApps(ctx *fiber.Ctx, input struct{}) ([]dtos.AppResponse, *fiberoapi.ErrorResponse) {
	requestId := ctx.Locals("requestid").(string)
	logger := ctrl.Logger.With().Str("request_id", requestId).Str("component", "http.api.v1.app.get_apps").Logger()

	authCtx, err := fiberoapi.GetAuthContext(ctx)
	if err != nil {
		logger.Error().Err(err).Msg("failed to get auth context")
		return nil, &fiberoapi.ErrorResponse{
			Code:    fiber.StatusUnauthorized,
			Details: "Authentication required",
			Type:    "AUTHENTICATION_REQUIRED",
		}
	}

	apps, err := ctrl.AppApp.GetAvailableApps(authCtx.UserID)
	if err != nil {
		logger.Error().Err(err).Str("user_id", authCtx.UserID).Msg("failed to get available apps")
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

func (ctrl Controller) GetApp(ctx *fiber.Ctx, input struct {
	Id string `path:"id"`
}) (*dtos.AppResponse, *fiberoapi.ErrorResponse) {
	requestId := ctx.Locals("requestid").(string)
	logger := ctrl.Logger.With().Str("request_id", requestId).Str("component", "http.api.v1.app.get_app").Logger()

	authCtx, err := fiberoapi.GetAuthContext(ctx)
	if err != nil {
		logger.Error().Err(err).Msg("failed to get auth context")
		return nil, &fiberoapi.ErrorResponse{
			Code:    fiber.StatusUnauthorized,
			Details: "Authentication required",
			Type:    "AUTHENTICATION_REQUIRED",
		}
	}

	app, err := ctrl.AppApp.ConnectToApp(authCtx.UserID, input.Id)
	if err != nil {
		logger.Error().Err(err).Str("app_id", input.Id).Msg("failed to get app")
		return nil, &fiberoapi.ErrorResponse{
			Code:    fiber.StatusNotFound,
			Details: err.Error(),
			Type:    "APP_NOT_FOUND",
		}
	}

	response := &dtos.AppResponse{
		Id:          app.Id,
		Name:        app.Name,
		Description: app.Description,
		Url:         app.Url,
		Icon:        app.Icon,
	}

	return response, nil
}

