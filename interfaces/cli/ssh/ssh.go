package ssh

import (
	"context"

	"github.com/labbs/bastion/application"
	"github.com/labbs/bastion/infrastructure"
	"github.com/labbs/bastion/infrastructure/config"
	"github.com/labbs/bastion/infrastructure/database"
	"github.com/labbs/bastion/infrastructure/logger"
	"github.com/labbs/bastion/infrastructure/persistence"
	sshserver "github.com/labbs/bastion/interfaces/ssh"
	"github.com/urfave/cli/v3"
)

// NewInstance creates a new CLI command for starting the SSH server.
func NewInstance(version string) *cli.Command {
	cfg := &config.Config{}
	cfg.Version = version
	sshFlags := getFlags(cfg)

	return &cli.Command{
		Name:  "ssh",
		Usage: "Start the bastion SSH server",
		Flags: sshFlags,
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return runSSHServer(*cfg)
		},
	}
}

// getFlags returns the list of CLI flags required for the SSH server command.
func getFlags(cfg *config.Config) (list []cli.Flag) {
	list = append(list, config.GenericFlags(cfg)...)
	list = append(list, config.LoggerFlags(cfg)...)
	list = append(list, config.DatabaseFlags(cfg)...)
	list = append(list, config.SSHFlags(cfg)...)
	return
}

// runSSHServer initializes the necessary dependencies and starts the SSH server.
func runSSHServer(cfg config.Config) error {
	var err error

	// Initialize dependencies
	deps := infrastructure.Deps{
		Config: cfg,
	}

	// Initialize logger
	deps.Logger = logger.NewLogger(cfg.Logger.Level, cfg.Logger.Pretty, cfg.Version)
	logger := deps.Logger.With().Str("component", "interfaces.cli.ssh.runsshserver").Logger()

	// Initialize database connection (gorm)
	deps.Database, err = database.Configure(deps.Config, deps.Logger)
	if err != nil {
		logger.Fatal().Err(err).Str("event", "ssh.runserver.database.configure").Msg("Failed to configure database connection")
		return err
	}

	// Initialize application services
	userPers := persistence.NewUserPers(deps.Database.Db)
	hostPers := persistence.NewHostPers(deps.Database.Db)
	sessionPers := persistence.NewSessionPers(deps.Database.Db)

	userApp := application.NewUserApp(deps.Config, deps.Logger, userPers, nil)
	sessionApp := application.NewSessionApp(deps.Config, deps.Logger, sessionPers, userApp)
	hostApp := application.NewHostApp(deps.Config, deps.Logger, hostPers, *sessionApp)

	// Initialize SSH server
	sshServer := sshserver.NewSSHServer(deps.Config, deps.Logger, hostApp, sessionApp)

	// Start SSH server
	logger.Info().Str("event", "ssh.runserver.ssh.listen").Msgf("Starting SSH server on port %d", cfg.SSH.Port)
	if err := sshServer.Start(); err != nil {
		logger.Fatal().Err(err).Str("event", "ssh.runserver.ssh.listen").Msg("Failed to start SSH server")
		return err
	}

	return nil
}

