package application

import (
	"fmt"

	"github.com/gofiber/fiber/v2/utils"
	"github.com/labbs/bastion/domain"
	"github.com/labbs/bastion/infrastructure/config"
	helperError "github.com/labbs/bastion/infrastructure/helpers/error"
	"github.com/rs/zerolog"
	"gorm.io/gorm"
)

type UserApp struct {
	Config    config.Config
	Logger    zerolog.Logger
	UserPres  domain.UserPers
	GroupPres domain.GroupPers
}

func NewUserApp(config config.Config, logger zerolog.Logger, userPers domain.UserPers, groupPers domain.GroupPers) *UserApp {
	return &UserApp{
		Config:    config,
		Logger:    logger,
		UserPres:  userPers,
		GroupPres: groupPers,
	}
}

func (c *UserApp) GetByEmail(email string) (*domain.User, error) {
	logger := c.Logger.With().Str("component", "application.user.get_by_email").Logger()

	user, err := c.UserPres.GetByEmail(email)
	if err != nil {
		logger.Error().Err(err).Str("email", email).Msg("failed to get user by email")
		return nil, err
	}
	return &user, nil
}

func (c *UserApp) GetByUserId(userId string) (*domain.User, error) {
	logger := c.Logger.With().Str("component", "application.user.get_by_user_id").Logger()

	user, err := c.UserPres.GetById(userId)
	if err != nil {
		logger.Error().Err(err).Str("user_id", userId).Msg("failed to get user by id")
		return nil, err
	}
	return &user, nil
}

func (c *UserApp) Create(user domain.User) (*domain.User, error) {
	logger := c.Logger.With().Str("component", "application.user.create").Logger()

	// Generate UUID for user
	user.Id = utils.UUIDv4()

	createdUser, err := c.UserPres.Create(user)
	if helperError.Catch(err) == gorm.ErrDuplicatedKey {
		logger.Warn().Str("email", user.Email).Msg("user with the same email already exists")
		return nil, fmt.Errorf("user with the same email already exists")
	} else if err != nil {
		logger.Error().Err(err).Str("email", user.Email).Msg("failed to create user")
		return nil, err
	}

	return &createdUser, nil
}
