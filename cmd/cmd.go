package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/labbs/bastion/interfaces/cli/migration"
	"github.com/labbs/bastion/interfaces/cli/server"
	"github.com/labbs/bastion/interfaces/cli/ssh"

	"github.com/urfave/cli/v3"
)

var version = "development"

// main is the entry point of the application.
// It sets up the CLI commands and handles configuration file loading.
func main() {
	sources := cli.NewValueSourceChain()
	cmd := &cli.Command{
		Name:    "Bastion",
		Version: version,
		Usage:   "Identity and access management system",
		Before: func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
			config := cmd.String("config")
			if len(config) > 0 {
				configFile := fmt.Sprintf("%s.yaml", cmd.String("config"))
				if _, err := os.Stat(configFile); os.IsNotExist(err) {
					return ctx, fmt.Errorf("could not load config file: %s", configFile)
				}

				sources.Append(cli.Files(configFile))
				return ctx, nil
			}

			return ctx, nil
		},
		Commands: []*cli.Command{
			server.NewInstance(version),
			migration.NewInstance(version),
			ssh.NewInstance(version),
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatalf("Error running command: %v", err)
	}
}
