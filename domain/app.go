package domain

import (
	"time"
)

type WebApp struct {
	Id          string
	Name        string
	Description string
	Url         string
	Icon        string
	// Active status
	Active bool

	CreatedAt time.Time
	UpdatedAt time.Time
}

func (w *WebApp) TableName() string {
	return "web_app"
}

type AppConnection struct {
	Id        string
	UserId    string
	AppId     string
	App       WebApp `gorm:"foreignKey:AppId;references:Id"`
	StartedAt time.Time
	EndedAt   *time.Time
	// Connection status
	Status string // active, closed
}

func (ac *AppConnection) TableName() string {
	return "app_connection"
}

type UserAppPermission struct {
	UserId string
	AppId  string
	User   User   `gorm:"foreignKey:UserId;references:Id"`
	App    WebApp `gorm:"foreignKey:AppId;references:Id"`
}

func (uap *UserAppPermission) TableName() string {
	return "user_app_permission"
}

type GroupAppPermission struct {
	GroupId string
	AppId   string
	Group   Group  `gorm:"foreignKey:GroupId;references:Id"`
	App     WebApp `gorm:"foreignKey:AppId;references:Id"`
}

func (gap *GroupAppPermission) TableName() string {
	return "group_app_permission"
}

type AppPers interface {
	GetById(id string) (WebApp, error)
	GetAll() ([]WebApp, error)
	GetByUserId(userId string) ([]WebApp, error)
	Create(app WebApp) (WebApp, error)
	Update(app WebApp) (WebApp, error)
	Delete(id string) error
}

type AppPermissionPers interface {
	// User permissions
	GrantUserPermission(userId, appId string) error
	RevokeUserPermission(userId, appId string) error
	GetUserPermissions(userId string) ([]UserAppPermission, error)
	GetAppUserPermissions(appId string) ([]UserAppPermission, error)
	
	// Group permissions
	GrantGroupPermission(groupId, appId string) error
	RevokeGroupPermission(groupId, appId string) error
	GetGroupPermissions(groupId string) ([]GroupAppPermission, error)
	GetAppGroupPermissions(appId string) ([]GroupAppPermission, error)
}

