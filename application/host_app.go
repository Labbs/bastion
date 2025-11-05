package application

import (
	"fmt"

	"github.com/labbs/bastion/domain"
	"github.com/labbs/bastion/infrastructure/config"
	"github.com/rs/zerolog"
)

type HostApp struct {
	Config     config.Config
	Logger     zerolog.Logger
	HostPers   domain.HostPers
	SessionApp SessionApp
}

func NewHostApp(config config.Config, logger zerolog.Logger, hostPers domain.HostPers, sessionApp SessionApp) *HostApp {
	return &HostApp{
		Config:     config,
		Logger:     logger,
		HostPers:   hostPers,
		SessionApp: sessionApp,
	}
}

func (c *HostApp) GetAvailableHosts(userId string) ([]domain.Host, error) {
	logger := c.Logger.With().Str("component", "application.host.get_available").Logger()

	hosts, err := c.HostPers.GetByUserId(userId)
	if err != nil {
		logger.Error().Err(err).Str("user_id", userId).Msg("failed to get available hosts")
		return nil, fmt.Errorf("failed to get available hosts: %w", err)
	}

	return hosts, nil
}

func (c *HostApp) ConnectToHost(userId string, hostId string) (*domain.Host, error) {
	logger := c.Logger.With().Str("component", "application.host.connect").Logger()

	host, err := c.HostPers.GetById(hostId)
	if err != nil {
		logger.Error().Err(err).Str("host_id", hostId).Msg("failed to get host")
		return nil, fmt.Errorf("host not found")
	}

	if !host.Active {
		logger.Warn().Str("host_id", hostId).Msg("attempt to connect to inactive host")
		return nil, fmt.Errorf("host is not active")
	}

	// Check permissions via session app
	// This will be implemented when we implement authorization
	// For now, we just check if user has access through GetByUserId
	availableHosts, err := c.GetAvailableHosts(userId)
	if err != nil {
		return nil, err
	}

	hasAccess := false
	for _, h := range availableHosts {
		if h.Id == hostId {
			hasAccess = true
			break
		}
	}

	if !hasAccess {
		logger.Warn().Str("user_id", userId).Str("host_id", hostId).Msg("user does not have access to host")
		return nil, fmt.Errorf("access denied")
	}

	return &host, nil
}

