package http

import (
	"github.com/labbs/bastion/infrastructure"
	"github.com/labbs/bastion/interfaces/http/dtos"

	"github.com/gofiber/fiber/v2"
	fiberoapi "github.com/labbs/fiber-oapi"
)

func setupSystemRoutes(deps infrastructure.Deps) {
	// Setup Health route
	fiberoapi.Get(deps.Http.FiberOapi, "/api/health",
		func(ctx *fiber.Ctx, input struct{}) (*dtos.HealthResponse, *fiberoapi.ErrorResponse) {
			return &dtos.HealthResponse{
				Status:  "ok",
				Service: "zotion",
				Version: deps.Config.Version,
			}, nil
		},
		fiberoapi.OpenAPIOptions{
			Summary:     "Health check",
			Description: "Returns the health status of the service",
			Tags:        []string{"Health"},
		},
	)
}
