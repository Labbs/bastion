package config

import (
	altsrc "github.com/urfave/cli-altsrc/v3"
	altsrcyaml "github.com/urfave/cli-altsrc/v3/yaml"
	"github.com/urfave/cli/v3"
)

func AuthFlags(cfg *Config) []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:        "auth.disable_admin_account",
			Value:       false,
			Destination: &cfg.Auth.DisableAdminAccount,
			Sources: cli.NewValueSourceChain(
				cli.EnvVar("AUTH_DISABLE_ADMIN_ACCOUNT"),
				altsrcyaml.YAML("auth.disable_admin_account", altsrc.NewStringPtrSourcer(&cfg.ConfigFile)),
			),
			Usage: "Disable the default admin account",
		},
	}
}

