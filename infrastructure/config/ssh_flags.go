package config

import (
	altsrc "github.com/urfave/cli-altsrc/v3"
	altsrcyaml "github.com/urfave/cli-altsrc/v3/yaml"
	"github.com/urfave/cli/v3"
)

func SSHFlags(cfg *Config) []cli.Flag {
	return []cli.Flag{
		&cli.IntFlag{
			Name:        "ssh.port",
			Value:       2222,
			Destination: &cfg.SSH.Port,
			Sources: cli.NewValueSourceChain(
				cli.EnvVar("SSH_PORT"),
				altsrcyaml.YAML("ssh.port", altsrc.NewStringPtrSourcer(&cfg.ConfigFile)),
			),
		},
		&cli.StringFlag{
			Name:        "ssh.host_key_path",
			Value:       "./ssh_host_key",
			Destination: &cfg.SSH.HostKeyPath,
			Sources: cli.NewValueSourceChain(
				cli.EnvVar("SSH_HOST_KEY_PATH"),
				altsrcyaml.YAML("ssh.host_key_path", altsrc.NewStringPtrSourcer(&cfg.ConfigFile)),
			),
		},
		&cli.StringFlag{
			Name:        "ssh.recording_path",
			Value:       "./recordings",
			Destination: &cfg.SSH.RecordingPath,
			Sources: cli.NewValueSourceChain(
				cli.EnvVar("SSH_RECORDING_PATH"),
				altsrcyaml.YAML("ssh.recording_path", altsrc.NewStringPtrSourcer(&cfg.ConfigFile)),
			),
		},
		&cli.BoolFlag{
			Name:        "ssh.enable_recording",
			Value:       true,
			Destination: &cfg.SSH.EnableRecording,
			Sources: cli.NewValueSourceChain(
				cli.EnvVar("SSH_ENABLE_RECORDING"),
				altsrcyaml.YAML("ssh.enable_recording", altsrc.NewStringPtrSourcer(&cfg.ConfigFile)),
			),
		},
	}
}

