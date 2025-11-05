package application

import (
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2/utils"
	"github.com/labbs/bastion/domain"
	"github.com/labbs/bastion/infrastructure/config"
	"github.com/labbs/bastion/infrastructure/helpers/tokenutil"
	fiberoapi "github.com/labbs/fiber-oapi"
	"github.com/rs/zerolog"
)

type SessionApp struct {
	Config      config.Config
	Logger      zerolog.Logger
	SessionPers domain.SessionPers
	UserApp     *UserApp
}

func NewSessionApp(config config.Config, logger zerolog.Logger, sessionPers domain.SessionPers, userApp *UserApp) *SessionApp {
	return &SessionApp{
		Config:      config,
		Logger:      logger,
		SessionPers: sessionPers,
		UserApp:     userApp,
	}
}

func (c *SessionApp) Create(session *domain.Session) error {
	logger := c.Logger.With().Str("component", "application.session.create").Logger()

	session.Id = utils.UUIDv4()

	err := c.SessionPers.Create(session)
	if err != nil {
		logger.Error().Err(err).Str("session_id", session.Id).Str("user_id", session.UserId).Msg("failed to create session")
		return err
	}

	return nil
}

func (c *SessionApp) DeleteExpired() error {
	// logger := c.Logger.With().Str("component", "application.session.delete_expired").Logger()

	return nil
}

func (c *SessionApp) ValidateToken(token string) (*fiberoapi.AuthContext, error) {
	logger := c.Logger.With().Str("component", "application.session.validate_token").Logger()

	sessionId, err := tokenutil.GetSessionIdFromToken(token, c.Config)
	if err != nil {
		logger.Error().Err(err).Str("token", token).Msg("failed to get session id from token")
		return nil, fmt.Errorf("invalid token")
	}

	session, err := c.SessionPers.GetById(sessionId)
	if err != nil {
		logger.Error().Err(err).Str("token", token).Msg("failed to get session by token")
		return nil, fmt.Errorf("invalid token")
	}

	if session.ExpiresAt.Before(time.Now()) {
		logger.Warn().Str("token", token).Msg("session has expired")
		return nil, fmt.Errorf("session has expired")
	}

	ctx := &fiberoapi.AuthContext{
		UserID: session.UserId,
		Claims: map[string]interface{}{
			"session_id": session.Id,
		},
	}

	return ctx, nil
}

func (c *SessionApp) HasRole(ctx *fiberoapi.AuthContext, role string) bool {
	logger := c.Logger.With().Str("component", "application.session.has_role").Logger()

	if ctx == nil {
		return false
	}

	user, err := c.UserApp.GetByUserId(ctx.UserID)
	if err != nil {
		logger.Error().Err(err).Str("user_id", ctx.UserID).Msg("failed to get user for role check")
		return false
	}

	// Admin has all roles
	if user.Role == domain.RoleAdmin {
		return true
	}

	// Check specific role
	return string(user.Role) == role
}

func (c *SessionApp) HasScope(ctx *fiberoapi.AuthContext, scope string) bool {
	logger := c.Logger.With().Str("component", "application.session.has_scope").Logger()

	if ctx == nil {
		return false
	}

	// For now, scopes are not implemented
	// This can be extended later for more granular permissions
	// Admin has all scopes
	user, err := c.UserApp.GetByUserId(ctx.UserID)
	if err != nil {
		logger.Error().Err(err).Str("user_id", ctx.UserID).Msg("failed to get user for scope check")
		return false
	}

	if user.Role == domain.RoleAdmin {
		return true
	}

	// Basic scope check - can be extended
	return false
}

func (c *SessionApp) CanAccessResource(ctx *fiberoapi.AuthContext, resourceType, resourceID, action string) (bool, error) {
	logger := c.Logger.With().Str("component", "application.session.can_access_resource").Logger()

	if ctx == nil {
		return false, fmt.Errorf("invalid context")
	}

	user, err := c.UserApp.GetByUserId(ctx.UserID)
	if err != nil {
		logger.Error().Err(err).Str("user_id", ctx.UserID).Msg("failed to get user for resource access check")
		return false, err
	}

	// Admin can access everything
	if user.Role == domain.RoleAdmin {
		return true, nil
	}

	// Check permissions based on resource type
	switch resourceType {
	case "host":
		// Check user_host_permission table
		// For now, we'll rely on the GetByUserId in HostApp which already filters by permissions
		// This is a simplified check - in production, you'd query the permission table directly
		return true, nil // Simplified - actual check done in HostApp.ConnectToHost
	case "app":
		// Check user_app_permission table
		// Similar to host - simplified check
		return true, nil // Simplified - actual check done in AppApp.ConnectToApp
	default:
		logger.Warn().Str("resource_type", resourceType).Msg("unknown resource type")
		return false, fmt.Errorf("unknown resource type: %s", resourceType)
	}
}

func (c *SessionApp) GetUserPermissions(ctx *fiberoapi.AuthContext, resourceType, resourceID string) (*fiberoapi.ResourcePermission, error) {
	logger := c.Logger.With().Str("component", "application.session.get_user_permissions").Logger()

	logger.Warn().Msg("not implemented")

	return nil, fmt.Errorf("not implemented")
}

func (c *SessionApp) InvalidateSession(sessionId string) error {
	logger := c.Logger.With().Str("component", "application.session.invalidate_session").Logger()

	err := c.SessionPers.DeleteById(sessionId)
	if err != nil {
		logger.Error().Err(err).Str("session_id", sessionId).Msg("failed to invalidate session")
		return err
	}

	return nil
}
