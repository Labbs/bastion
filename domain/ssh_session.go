package domain

import (
	"time"
)

type SSHSessionRecord struct {
	Id        string
	UserId    string
	HostId    string
	User      User `gorm:"foreignKey:UserId;references:Id"`
	Host      Host `gorm:"foreignKey:HostId;references:Id"`
	StartedAt time.Time
	EndedAt   *time.Time
	// Recording data - can be stored as file path or in DB as blob
	RecordingPath string
	// Recording format: text, json, binary
	Format string
	// Session metadata
	ClientIP     string
	ClientUser   string
	SessionId    string
}

func (ssr *SSHSessionRecord) TableName() string {
	return "ssh_session_record"
}

