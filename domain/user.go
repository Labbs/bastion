package domain

import (
	"time"
)

type User struct {
	Id       string
	Username string
	Email    string
	Password string

	AvatarUrl   string
	Preferences JSONB
	Active      bool

	Role Role `gorm:"type:role;default:'user'"`

	CreatedAt time.Time
	UpdatedAt time.Time
}

func (u *User) TableName() string {
	return "user"
}

type UserPers interface {
	GetByUsername(username string) (User, error)
	GetByEmail(email string) (User, error)
	GetById(id string) (User, error)
	GetAll() ([]User, error)
	Create(user User) (User, error)
	Update(user User) (User, error)
	Delete(id string) error
}
