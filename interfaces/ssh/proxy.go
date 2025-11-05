package ssh

import (
	"fmt"
	"io"
	"time"

	"github.com/labbs/bastion/application"
	"github.com/labbs/bastion/domain"
	"github.com/labbs/bastion/infrastructure/config"
	"github.com/labbs/bastion/infrastructure/recording"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/ssh"
)

type SSHProxy struct {
	Config     config.Config
	Logger     zerolog.Logger
	HostApp    *application.HostApp
	Recorder   *recording.SSHSessionRecorder
	Channel    ssh.Channel
	Host       domain.Host
}

func NewSSHProxy(cfg config.Config, logger zerolog.Logger, hostApp *application.HostApp, recorder *recording.SSHSessionRecorder, channel ssh.Channel, host domain.Host) *SSHProxy {
	return &SSHProxy{
		Config:   cfg,
		Logger:   logger,
		HostApp:  hostApp,
		Recorder: recorder,
		Channel:  channel,
		Host:     host,
	}
}

func (p *SSHProxy) Connect() error {
	logger := p.Logger.With().Str("component", "ssh.proxy.connect").Str("host", p.Host.Hostname).Logger()

	// Configure SSH client
	clientConfig := &ssh.ClientConfig{
		User:            p.Host.Username,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // In production, verify host key
		Timeout:         30 * time.Second,
	}

	// Set up authentication based on auth method
	// Note: In production, you'd load keys from secure storage
	switch p.Host.AuthMethod {
	case "password":
		if p.Host.Password != "" {
			clientConfig.Auth = []ssh.AuthMethod{
				ssh.Password(p.Host.Password),
			}
		}
	case "key":
		// TODO: Load and parse private key
		logger.Warn().Msg("key authentication not yet implemented")
		return fmt.Errorf("key authentication not yet implemented")
	case "both":
		// TODO: Support both methods
		if p.Host.Password != "" {
			clientConfig.Auth = []ssh.AuthMethod{
				ssh.Password(p.Host.Password),
			}
		}
	}

	// Connect to target host
	targetAddr := fmt.Sprintf("%s:%d", p.Host.Hostname, p.Host.Port)
	client, err := ssh.Dial("tcp", targetAddr, clientConfig)
	if err != nil {
		logger.Error().Err(err).Str("target", targetAddr).Msg("failed to connect to target host")
		return fmt.Errorf("failed to connect to %s: %w", targetAddr, err)
	}
	defer client.Close()

	logger.Info().Str("target", targetAddr).Msg("connected to target host")

	// Create session
	session, err := client.NewSession()
	if err != nil {
		logger.Error().Err(err).Msg("failed to create session")
		return fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	// Set up terminal
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}

	if err := session.RequestPty("xterm", 80, 24, modes); err != nil {
		logger.Error().Err(err).Msg("failed to request pty")
		return fmt.Errorf("failed to request pty: %w", err)
	}

	// Set up I/O forwarding with recording
	sessionStdin, _ := session.StdinPipe()
	sessionStdout, _ := session.StdoutPipe()
	sessionStderr, _ := session.StderrPipe()

	// Forward stdin from channel to session with recording
	go func() {
		io.Copy(sessionStdin, io.TeeReader(p.Channel, &recordingWriter{recorder: p.Recorder, direction: "INPUT"}))
	}()

	// Forward stdout from session to channel with recording
	go func() {
		io.Copy(p.Channel, io.TeeReader(sessionStdout, &recordingWriter{recorder: p.Recorder, direction: "OUTPUT"}))
	}()

	// Forward stderr from session to channel with recording
	go func() {
		io.Copy(p.Channel.Stderr(), io.TeeReader(sessionStderr, &recordingWriter{recorder: p.Recorder, direction: "ERROR"}))
	}()

	// Start shell
	if err := session.Shell(); err != nil {
		logger.Error().Err(err).Msg("failed to start shell")
		return fmt.Errorf("failed to start shell: %w", err)
	}

	// Wait for session to end
	err = session.Wait()
	if err != nil && err != io.EOF {
		logger.Error().Err(err).Msg("session ended with error")
	}

	return nil
}

type recordingWriter struct {
	recorder  *recording.SSHSessionRecorder
	direction string
}

func (w *recordingWriter) Write(p []byte) (n int, err error) {
	if w.recorder != nil {
		w.recorder.Record(p, w.direction)
	}
	return len(p), nil
}

