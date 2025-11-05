package persistence

import (
	"github.com/labbs/bastion/domain"
	"gorm.io/gorm"
)

type appPermissionPers struct {
	db *gorm.DB
}

func NewAppPermissionPers(db *gorm.DB) *appPermissionPers {
	return &appPermissionPers{db: db}
}

// User permissions
func (a *appPermissionPers) GrantUserPermission(userId, appId string) error {
	// Check if permission already exists
	var existing domain.UserAppPermission
	err := a.db.Where("user_id = ? AND app_id = ?", userId, appId).First(&existing).Error
	if err == nil {
		// Permission already exists, nothing to do
		return nil
	}
	if err != gorm.ErrRecordNotFound {
		return err
	}

	// Create new permission
	perm := domain.UserAppPermission{
		UserId: userId,
		AppId:  appId,
	}
	return a.db.Create(&perm).Error
}

func (a *appPermissionPers) RevokeUserPermission(userId, appId string) error {
	return a.db.Where("user_id = ? AND app_id = ?", userId, appId).Delete(&domain.UserAppPermission{}).Error
}

func (a *appPermissionPers) GetUserPermissions(userId string) ([]domain.UserAppPermission, error) {
	var perms []domain.UserAppPermission
	err := a.db.Where("user_id = ?", userId).Find(&perms).Error
	return perms, err
}

func (a *appPermissionPers) GetAppUserPermissions(appId string) ([]domain.UserAppPermission, error) {
	var perms []domain.UserAppPermission
	err := a.db.Preload("User").Preload("App").Where("app_id = ?", appId).Find(&perms).Error
	return perms, err
}

// Group permissions
func (a *appPermissionPers) GrantGroupPermission(groupId, appId string) error {
	// Check if permission already exists
	var existing domain.GroupAppPermission
	err := a.db.Where("group_id = ? AND app_id = ?", groupId, appId).First(&existing).Error
	if err == nil {
		// Permission already exists, nothing to do
		return nil
	}
	if err != gorm.ErrRecordNotFound {
		return err
	}

	// Create new permission
	perm := domain.GroupAppPermission{
		GroupId: groupId,
		AppId:   appId,
	}
	return a.db.Create(&perm).Error
}

func (a *appPermissionPers) RevokeGroupPermission(groupId, appId string) error {
	return a.db.Where("group_id = ? AND app_id = ?", groupId, appId).Delete(&domain.GroupAppPermission{}).Error
}

func (a *appPermissionPers) GetGroupPermissions(groupId string) ([]domain.GroupAppPermission, error) {
	var perms []domain.GroupAppPermission
	err := a.db.Where("group_id = ?", groupId).Find(&perms).Error
	return perms, err
}

func (a *appPermissionPers) GetAppGroupPermissions(appId string) ([]domain.GroupAppPermission, error) {
	var perms []domain.GroupAppPermission
	err := a.db.Preload("Group").Preload("App").Where("app_id = ?", appId).Find(&perms).Error
	return perms, err
}

