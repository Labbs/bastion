package application

import (
	"fmt"

	"github.com/labbs/bastion/domain"
	"github.com/labbs/bastion/infrastructure/config"
	"github.com/rs/zerolog"
)

type AppApp struct {
	Config     config.Config
	Logger     zerolog.Logger
	AppPers    domain.AppPers
	SessionApp SessionApp
}

func NewAppApp(config config.Config, logger zerolog.Logger, appPers domain.AppPers, sessionApp SessionApp) *AppApp {
	return &AppApp{
		Config:     config,
		Logger:     logger,
		AppPers:    appPers,
		SessionApp: sessionApp,
	}
}

func (c *AppApp) GetAvailableApps(userId string) ([]domain.WebApp, error) {
	logger := c.Logger.With().Str("component", "application.app.get_available").Logger()

	apps, err := c.AppPers.GetByUserId(userId)
	if err != nil {
		logger.Error().Err(err).Str("user_id", userId).Msg("failed to get available apps")
		return nil, fmt.Errorf("failed to get available apps: %w", err)
	}

	return apps, nil
}

func (c *AppApp) ConnectToApp(userId string, appId string) (*domain.WebApp, error) {
	logger := c.Logger.With().Str("component", "application.app.connect").Logger()

	app, err := c.AppPers.GetById(appId)
	if err != nil {
		logger.Error().Err(err).Str("app_id", appId).Msg("failed to get app")
		return nil, fmt.Errorf("app not found")
	}

	if !app.Active {
		logger.Warn().Str("app_id", appId).Msg("attempt to connect to inactive app")
		return nil, fmt.Errorf("app is not active")
	}

	// Check permissions via session app
	// This will be implemented when we implement authorization
	// For now, we just check if user has access through GetByUserId
	availableApps, err := c.GetAvailableApps(userId)
	if err != nil {
		return nil, err
	}

	hasAccess := false
	for _, a := range availableApps {
		if a.Id == appId {
			hasAccess = true
			break
		}
	}

	if !hasAccess {
		logger.Warn().Str("user_id", userId).Str("app_id", appId).Msg("user does not have access to app")
		return nil, fmt.Errorf("access denied")
	}

	return &app, nil
}

