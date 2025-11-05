package infrastructure

import (
	"github.com/labbs/bastion/application"
	"github.com/labbs/bastion/infrastructure/config"
	"github.com/labbs/bastion/infrastructure/cronscheduler"
	"github.com/labbs/bastion/infrastructure/database"
	"github.com/labbs/bastion/infrastructure/http"
	"github.com/rs/zerolog"
)

type Deps struct {
	Config        config.Config
	Logger        zerolog.Logger
	Http          http.Config
	CronScheduler cronscheduler.Config
	Database      database.Config

	UserApp    *application.UserApp
	SessionApp *application.SessionApp
	AuthApp    *application.AuthApp
	HostApp    *application.HostApp
	AppApp     *application.AppApp
	AdminApp   *application.AdminApp
}
