package domain

import (
	"time"
)

type Host struct {
	Id          string
	Name        string
	Description string
	Hostname    string
	Port        int
	Username    string
	// Connection method: password, key, or both
	AuthMethod  string
	// For password auth
	Password string `gorm:"-"`
	// For key auth - path to private key or key content
	PrivateKey string `gorm:"-"`
	// Active status
	Active bool

	CreatedAt time.Time
	UpdatedAt time.Time
}

func (h *Host) TableName() string {
	return "host"
}

type HostConnection struct {
	Id        string
	UserId    string
	HostId    string
	Host      Host `gorm:"foreignKey:HostId;references:Id"`
	StartedAt time.Time
	EndedAt   *time.Time
	// Connection status
	Status string // active, closed, error
}

func (hc *HostConnection) TableName() string {
	return "host_connection"
}

type UserHostPermission struct {
	UserId string
	HostId string
	User   User `gorm:"foreignKey:UserId;references:Id"`
	Host   Host `gorm:"foreignKey:HostId;references:Id"`
	// Permission level: read, write, admin
	Permission string
}

func (uhp *UserHostPermission) TableName() string {
	return "user_host_permission"
}

type HostPers interface {
	GetById(id string) (Host, error)
	GetAll() ([]Host, error)
	GetByUserId(userId string) ([]Host, error)
	Create(host Host) (Host, error)
	Update(host Host) (Host, error)
	Delete(id string) error
}

