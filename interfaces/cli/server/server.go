package server

import (
	"context"
	"strconv"

	"github.com/labbs/bastion/application"
	"github.com/labbs/bastion/infrastructure"
	"github.com/labbs/bastion/infrastructure/config"
	"github.com/labbs/bastion/infrastructure/cronscheduler"
	"github.com/labbs/bastion/infrastructure/database"
	"github.com/labbs/bastion/infrastructure/http"
	"github.com/labbs/bastion/infrastructure/jobs"
	"github.com/labbs/bastion/infrastructure/logger"
	"github.com/labbs/bastion/infrastructure/persistence"
	routes "github.com/labbs/bastion/interfaces/http"

	"github.com/urfave/cli/v3"
	"github.com/valyala/fasthttp"
)

// NewInstance creates a new CLI command for starting the server.
// It's called by the main application to add the "server" command to the CLI.
func NewInstance(version string) *cli.Command {
	cfg := &config.Config{}
	cfg.Version = version
	serverFlags := getFlags(cfg)

	return &cli.Command{
		Name:  "server",
		Usage: "Start the bastion HTTP server",
		Flags: serverFlags,
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return runServer(*cfg)
		},
	}
}

// getFlags returns the list of CLI flags required for the server command.
func getFlags(cfg *config.Config) (list []cli.Flag) {
	list = append(list, config.GenericFlags(cfg)...)
	list = append(list, config.ServerFlags(cfg)...)
	list = append(list, config.LoggerFlags(cfg)...)
	list = append(list, config.DatabaseFlags(cfg)...)
	list = append(list, config.SessionFlags(cfg)...)
	list = append(list, config.RegistrationFlags(cfg)...)
	list = append(list, config.AuthFlags(cfg)...)
	return
}

// runServer initializes the necessary dependencies and starts the HTTP server.
func runServer(cfg config.Config) error {
	var err error

	// Initialize dependencies
	deps := infrastructure.Deps{
		Config: cfg,
	}

	// Initialize logger
	deps.Logger = logger.NewLogger(cfg.Logger.Level, cfg.Logger.Pretty, cfg.Version)
	logger := deps.Logger.With().Str("component", "interfaces.cli.http.runserver").Logger()

	// Initialize other cron scheduler (go-cron)
	deps.CronScheduler, err = cronscheduler.Configure(deps.Logger)
	if err != nil {
		logger.Fatal().Err(err).Str("event", "http.runserver.cronscheduler.configure").Msg("Failed to configure cron scheduler")
		return err
	}

	// Initialize database connection (gorm)
	deps.Database, err = database.Configure(deps.Config, deps.Logger)
	if err != nil {
		logger.Fatal().Err(err).Str("event", "http.runserver.database.configure").Msg("Failed to configure database connection")
		return err
	}

	// Initialize application services
	userPers := persistence.NewUserPers(deps.Database.Db)
	groupPers := persistence.NewGroupPers(deps.Database.Db)
	sessionPers := persistence.NewSessionPers(deps.Database.Db)
	hostPers := persistence.NewHostPers(deps.Database.Db)
	appPers := persistence.NewAppPers(deps.Database.Db)

	deps.UserApp = application.NewUserApp(deps.Config, deps.Logger, userPers, groupPers)
	deps.SessionApp = application.NewSessionApp(deps.Config, deps.Logger, sessionPers, deps.UserApp)
	deps.AuthApp = application.NewAuthApp(deps.Config, deps.Logger, *deps.UserApp, *deps.SessionApp)
	deps.HostApp = application.NewHostApp(deps.Config, deps.Logger, hostPers, *deps.SessionApp)
	deps.AppApp = application.NewAppApp(deps.Config, deps.Logger, appPers, *deps.SessionApp)

	appPermissionPers := persistence.NewAppPermissionPers(deps.Database.Db)
	deps.AdminApp = application.NewAdminApp(deps.Config, deps.Logger, deps.UserApp, deps.HostApp, deps.AppApp, appPermissionPers, groupPers)

	// Initialize HTTP server (fiber + fiberoapi)
	deps.Http, err = http.Configure(deps.Config, deps.Logger, *deps.SessionApp, true)
	if err != nil {
		logger.Fatal().Err(err).Str("event", "http.runserver.http.configure").Msg("Failed to configure HTTP server")
		return err
	}

	// Setup cron jobs
	configJobs := jobs.Config{
		Logger:        deps.Logger,
		CronScheduler: deps.CronScheduler,
		SessionApp:    *deps.SessionApp,
	}

	err = configJobs.SetupJobs()
	if err != nil {
		logger.Fatal().Err(err).Str("event", "http.runserver.jobs.setup").Msg("Failed to setup cron jobs")
		return err
	}

	// Setup routes
	routes.SetupRoutes(deps)

	// Start HTTP server avec configuration Fasthttp personnalisée pour supporter les URLs longues
	logger.Info().Str("event", "http.runserver.http.listen").Msgf("Starting HTTP server on port %d", cfg.Server.Port)

	// Configuration personnalisée du serveur Fasthttp pour augmenter la limite d'URI
	// Par défaut, Fasthttp limite les URIs à environ 8KB
	// On augmente à 128KB pour supporter les URLs très longues de Google
	customServer := &fasthttp.Server{
		Handler:            deps.Http.Fiber.Handler(),
		Name:               "bastion",
		ReadBufferSize:     131072,           // 128KB
		MaxRequestBodySize: 10 * 1024 * 1024, // 10MB
		// IMPORTANT: Augmenter la limite de la première ligne de la requête HTTP
		// qui contient l'URI. Par défaut c'est 8KB dans Fasthttp
		ReadTimeout:  0, // Pas de timeout pour éviter les problèmes avec les requêtes longues
		WriteTimeout: 0,
	}

	logger.Info().
		Int("ReadBufferSize", customServer.ReadBufferSize).
		Int("MaxRequestBodySize", customServer.MaxRequestBodySize).
		Msg("Custom Fasthttp server configured - ReadBufferSize=128KB, MaxRequestBodySize=10MB")

	err = customServer.ListenAndServe(":" + strconv.Itoa(cfg.Server.Port))
	if err != nil {
		logger.Fatal().Err(err).Str("event", "http.runserver.http.listen").Msg("Failed to start HTTP server")
		return err
	}

	return nil
}
