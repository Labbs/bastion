package user

import (
	"github.com/gofiber/fiber/v2"
	"github.com/labbs/bastion/infrastructure/helpers/mapper"
	"github.com/labbs/bastion/interfaces/http/v1/user/dtos"
	fiberoapi "github.com/labbs/fiber-oapi"
)

func (ctrl *Controller) GetProfile(ctx *fiber.Ctx, input struct{}) (*dtos.ProfileResponse, *fiberoapi.ErrorResponse) {
	requestId := ctx.Locals("requestid").(string)
	logger := ctrl.Logger.With().Str("request_id", requestId).Str("component", "http.api.v1.user.get_profile").Logger()

	// Get the authenticated user context
	authCtx, err := fiberoapi.GetAuthContext(ctx)
	if err != nil {
		logger.Error().Err(err).Msg("failed to get auth context")
		return nil, &fiberoapi.ErrorResponse{
			Code:    fiber.StatusUnauthorized,
			Details: "Authentication required",
			Type:    "AUTHENTICATION_REQUIRED",
		}
	}

	user, err := ctrl.UserApp.GetByUserId(authCtx.UserID)
	if err != nil {
		logger.Error().Err(err).Msg("failed to get user by id")
		return nil, &fiberoapi.ErrorResponse{
			Code:    fiber.StatusInternalServerError,
			Details: "Failed to retrieve user",
			Type:    "INTERNAL_SERVER_ERROR",
		}
	}

	profile := dtos.ProfileResponse{}
	err = mapper.MapStructByFieldNames(user, &profile)
	if err != nil {
		logger.Error().Err(err).Msg("failed to map user to profile")
		return nil, &fiberoapi.ErrorResponse{
			Code:    fiber.StatusInternalServerError,
			Details: "Failed to retrieve profile",
			Type:    "INTERNAL_SERVER_ERROR",
		}
	}

	return &profile, nil
}
