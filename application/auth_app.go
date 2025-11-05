package application

import (
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/labbs/bastion/domain"
	"github.com/labbs/bastion/infrastructure/config"
	"github.com/labbs/bastion/infrastructure/helpers/tokenutil"
	"github.com/labbs/bastion/interfaces/http/v1/auth/dtos"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/bcrypt"
)

type AuthApp struct {
	Config     config.Config
	Logger     zerolog.Logger
	UserApp    UserApp
	SessionApp SessionApp
}

func NewAuthApp(config config.Config, logger zerolog.Logger, userApp UserApp, sessionApp SessionApp) *AuthApp {
	return &AuthApp{
		Config:     config,
		Logger:     logger,
		UserApp:    userApp,
		SessionApp: sessionApp,
	}
}

func (c *AuthApp) Authenticate(email, password string, ctx *fiber.Ctx) (*dtos.LoginResponse, error) {
	logger := c.Logger.With().Str("component", "application.auth.authenticate").Logger()

	// Check if admin account is disabled
	if email == "admin@bastion.local" && c.Config.Auth.DisableAdminAccount {
		logger.Warn().Str("email", email).Msg("attempt to authenticate disabled admin account")
		return nil, fmt.Errorf("admin account is disabled")
	}

	user, err := c.UserApp.GetByEmail(email)
	if err != nil {
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}

	if !user.Active {
		logger.Warn().Str("email", email).Msg("attempt to authenticate inactive user")
		return nil, fmt.Errorf("user is not active")
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		logger.Warn().Str("email", email).Msg("invalid password attempt")
		return nil, fmt.Errorf("invalid credentials")
	}

	session := &domain.Session{
		UserId:    user.Id,
		UserAgent: ctx.Get("User-Agent"),
		IpAddress: ctx.IP(),
		ExpiresAt: time.Now().Add(time.Minute * time.Duration(c.Config.Session.ExpirationMinutes)),
	}

	err = c.SessionApp.Create(session)
	if err != nil {
		logger.Error().Err(err).Str("user_id", user.Id).Msg("failed to create session")
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	accessToken, err := tokenutil.CreateAccessToken(user.Id, session.Id, c.Config)
	if err != nil {
		logger.Error().Err(err).Str("user_id", user.Id).Str("session_id", session.Id).Msg("failed to create access token")
		return nil, fmt.Errorf("failed to create access token: %w", err)
	}

	return &dtos.LoginResponse{
		Token: accessToken,
	}, nil
}

func (c *AuthApp) Register(username, email, password string) error {
	logger := c.Logger.With().Str("component", "application.auth.register").Logger()

	// check if the email is already in use
	_, err := c.UserApp.GetByEmail(email)
	if err == nil {
		return fmt.Errorf("email is already in use")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		logger.Error().Err(err).Str("email", email).Msg("failed to hash password")
		return fmt.Errorf("failed to hash password: %w", err)
	}

	user := domain.User{
		Username: username,
		Email:    email,
		Password: string(hashedPassword),
		Active:   true,
	}

	_, err = c.UserApp.Create(user)
	if err != nil {
		logger.Error().Err(err).Str("email", email).Msg("failed to create user")
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

func (c *AuthApp) Logout(sessionId string) error {
	logger := c.Logger.With().Str("component", "application.auth.logout").Logger()

	err := c.SessionApp.InvalidateSession(sessionId)
	if err != nil {
		logger.Error().Err(err).Str("session_id", sessionId).Msg("failed to invalidate session")
		return fmt.Errorf("failed to invalidate session: %w", err)
	}

	return nil
}
