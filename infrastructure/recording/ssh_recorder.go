package recording

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/labbs/bastion/infrastructure/config"
	"github.com/rs/zerolog"
)

type SSHSessionRecorder struct {
	Config      config.Config
	Logger      zerolog.Logger
	SessionId   string
	UserId      string
	HostId      string
	RecordingPath string
	File        *os.File
	StartedAt   time.Time
}

func NewSSHSessionRecorder(cfg config.Config, logger zerolog.Logger, sessionId, userId, hostId string) (*SSHSessionRecorder, error) {
	recorder := &SSHSessionRecorder{
		Config:        cfg,
		Logger:        logger,
		SessionId:     sessionId,
		UserId:        userId,
		HostId:        hostId,
		RecordingPath: cfg.SSH.RecordingPath,
		StartedAt:     time.Now(),
	}

	if !cfg.SSH.EnableRecording {
		return recorder, nil
	}

	// Create recording directory if it doesn't exist
	if err := os.MkdirAll(recorder.RecordingPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create recording directory: %w", err)
	}

	// Create recording file
	filename := fmt.Sprintf("session_%s_%s.txt", recorder.UserId, recorder.SessionId)
	filepath := filepath.Join(recorder.RecordingPath, filename)

	file, err := os.Create(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to create recording file: %w", err)
	}

	recorder.File = file

	// Write header
	recorder.File.WriteString(fmt.Sprintf("=== SSH Session Recording ===\n"))
	recorder.File.WriteString(fmt.Sprintf("Session ID: %s\n", recorder.SessionId))
	recorder.File.WriteString(fmt.Sprintf("User ID: %s\n", recorder.UserId))
	recorder.File.WriteString(fmt.Sprintf("Host ID: %s\n", recorder.HostId))
	recorder.File.WriteString(fmt.Sprintf("Started at: %s\n", recorder.StartedAt.Format(time.RFC3339)))
	recorder.File.WriteString(fmt.Sprintf("================================\n\n"))

	return recorder, nil
}

func (r *SSHSessionRecorder) Record(data []byte, direction string) error {
	if r.File == nil {
		return nil // Recording disabled
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	prefix := fmt.Sprintf("[%s] [%s] ", timestamp, direction)
	
	_, err := r.File.WriteString(prefix + string(data))
	return err
}

func (r *SSHSessionRecorder) RecordReader(reader io.Reader, direction string) error {
	if r.File == nil {
		return nil // Recording disabled
	}

	buffer := make([]byte, 1024)
	for {
		n, err := reader.Read(buffer)
		if n > 0 {
			if recordErr := r.Record(buffer[:n], direction); recordErr != nil {
				return recordErr
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *SSHSessionRecorder) Close() error {
	if r.File == nil {
		return nil
	}

	r.File.WriteString(fmt.Sprintf("\n=== Session Ended at: %s ===\n", time.Now().Format(time.RFC3339)))
	return r.File.Close()
}

func (r *SSHSessionRecorder) GetRecordingPath() string {
	if r.File == nil {
		return ""
	}
	return r.File.Name()
}

