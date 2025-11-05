package ssh

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strconv"

	"github.com/gofiber/fiber/v2/utils"
	"github.com/labbs/bastion/application"
	"github.com/labbs/bastion/infrastructure/config"
	"github.com/labbs/bastion/infrastructure/recording"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/ssh"
)

type Server struct {
	Config     config.Config
	Logger     zerolog.Logger
	HostApp    *application.HostApp
	SessionApp *application.SessionApp
	listener   net.Listener
}

func NewSSHServer(cfg config.Config, logger zerolog.Logger, hostApp *application.HostApp, sessionApp *application.SessionApp) *Server {
	return &Server{
		Config:     cfg,
		Logger:     logger,
		HostApp:    hostApp,
		SessionApp: sessionApp,
	}
}

func (s *Server) Start() error {
	logger := s.Logger.With().Str("component", "ssh.server").Logger()

	// Load or generate host key
	signer, err := s.loadOrGenerateHostKey()
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to load or generate host key")
		return err
	}

	// Configure SSH server
	serverConfig := &ssh.ServerConfig{
		PublicKeyCallback: s.publicKeyCallback,
		PasswordCallback:  s.passwordCallback,
	}
	serverConfig.AddHostKey(signer)

	// Start listening
	addr := ":" + strconv.Itoa(s.Config.SSH.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		logger.Fatal().Err(err).Str("addr", addr).Msg("failed to start SSH server")
		return err
	}

	s.listener = listener
	logger.Info().Str("addr", addr).Msg("SSH server started")

	// Accept connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Error().Err(err).Msg("failed to accept connection")
			continue
		}

		go s.handleConnection(conn, serverConfig)
	}
}

func (s *Server) Stop() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *Server) handleConnection(conn net.Conn, config *ssh.ServerConfig) {
	logger := s.Logger.With().Str("component", "ssh.server.handle_connection").Logger()
	defer conn.Close()

	// Perform SSH handshake
	serverConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		logger.Error().Err(err).Msg("SSH handshake failed")
		return
	}
	defer serverConn.Close()

	logger.Info().Str("user", serverConn.User()).Str("remote_addr", serverConn.RemoteAddr().String()).Msg("SSH connection established")

	// Handle global requests
	go ssh.DiscardRequests(reqs)

	// Handle channels
	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			logger.Error().Err(err).Msg("failed to accept channel")
			continue
		}

		// Handle channel requests
		go func(in <-chan *ssh.Request) {
			for req := range in {
				switch req.Type {
				case "shell":
					req.Reply(true, nil)
				case "pty-req":
					req.Reply(true, nil)
				default:
					req.Reply(false, nil)
				}
			}
		}(requests)

		// Get user ID from connection metadata
		// This would be set during authentication
		userId := serverConn.User() // In a real implementation, extract from auth metadata

		// Get available hosts for user
		hosts, err := s.HostApp.GetAvailableHosts(userId)
		if err != nil {
			logger.Error().Err(err).Str("user_id", userId).Msg("failed to get available hosts")
			channel.Write([]byte("Error: Failed to get available hosts\n"))
			channel.Close()
			continue
		}

		// Display menu
		menu := NewMenu(s.Logger, hosts, channel, channel)
		choice, err := menu.Display()
		if err != nil {
			logger.Error().Err(err).Msg("failed to display menu")
			channel.Write([]byte(fmt.Sprintf("Error: %s\n", err.Error())))
			channel.Close()
			continue
		}

		selectedHost := hosts[choice]

		// Create session recorder
		sessionId := utils.UUIDv4()
		recorder, err := recording.NewSSHSessionRecorder(s.Config, s.Logger, sessionId, userId, selectedHost.Id)
		if err != nil {
			logger.Error().Err(err).Msg("failed to create session recorder")
			// Continue without recording
		}
		defer recorder.Close()

		// Create proxy connection
		proxy := NewSSHProxy(s.Config, s.Logger, s.HostApp, recorder, channel, selectedHost)
		if err := proxy.Connect(); err != nil {
			logger.Error().Err(err).Msg("failed to connect via proxy")
			channel.Write([]byte(fmt.Sprintf("Error: %s\n", err.Error())))
		}

		channel.Close()
	}
}

func (s *Server) publicKeyCallback(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	logger := s.Logger.With().Str("component", "ssh.server.public_key_callback").Logger()
	
	// TODO: Implement public key authentication
	// For now, we'll use password authentication
	logger.Warn().Msg("public key authentication not yet implemented")
	return nil, fmt.Errorf("public key authentication not yet implemented")
}

func (s *Server) passwordCallback(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	logger := s.Logger.With().Str("component", "ssh.server.password_callback").Logger()

	// Extract user ID from username (format: user_id@bastion)
	// For now, we'll use a token-based approach
	// The username should be a token that can be validated
	username := conn.User()
	
	// TODO: Implement proper token validation
	// For now, this is a placeholder
	logger.Info().Str("username", username).Msg("password authentication attempt")
	
	// Validate token and get user ID
	// This is simplified - in production, you'd validate a JWT token
	return &ssh.Permissions{
		Extensions: map[string]string{
			"user_id": username, // This should be extracted from token
		},
	}, nil
}

func (s *Server) loadOrGenerateHostKey() (ssh.Signer, error) {
	logger := s.Logger.With().Str("component", "ssh.server.host_key").Logger()

	// Try to load existing key
	if _, err := os.Stat(s.Config.SSH.HostKeyPath); err == nil {
		privateBytes, err := os.ReadFile(s.Config.SSH.HostKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read host key: %w", err)
		}

		privateKey, err := ssh.ParsePrivateKey(privateBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse host key: %w", err)
		}

		logger.Info().Str("path", s.Config.SSH.HostKeyPath).Msg("loaded existing host key")
		return privateKey, nil
	}

	// Generate new key
	logger.Info().Msg("generating new host key")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	// Encode private key
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	// Write to file
	if err := os.MkdirAll(s.Config.SSH.HostKeyPath[:len(s.Config.SSH.HostKeyPath)-len("ssh_host_key")], 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory: %w", err)
	}

	file, err := os.Create(s.Config.SSH.HostKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create key file: %w", err)
	}
	defer file.Close()

	if err := pem.Encode(file, privateKeyPEM); err != nil {
		return nil, fmt.Errorf("failed to encode key: %w", err)
	}

	// Parse as SSH key
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}

	logger.Info().Str("path", s.Config.SSH.HostKeyPath).Msg("generated new host key")
	return signer, nil
}

