package persistence

import (
	"github.com/labbs/bastion/domain"
	"gorm.io/gorm"
)

type appPers struct {
	db *gorm.DB
}

func NewAppPers(db *gorm.DB) *appPers {
	return &appPers{db: db}
}

func (a *appPers) GetById(id string) (domain.WebApp, error) {
	var app domain.WebApp
	err := a.db.Where("id = ?", id).First(&app).Error
	return app, err
}

func (a *appPers) GetAll() ([]domain.WebApp, error) {
	var apps []domain.WebApp
	err := a.db.Where("active = ?", true).Find(&apps).Error
	return apps, err
}

func (a *appPers) GetByUserId(userId string) ([]domain.WebApp, error) {
	var apps []domain.WebApp
	
	// Get apps directly assigned to user
	err := a.db.
		Joins("JOIN user_app_permission ON user_app_permission.app_id = web_app.id").
		Where("user_app_permission.user_id = ? AND web_app.active = ?", userId, true).
		Find(&apps).Error
	if err != nil {
		return nil, err
	}
	
	// Get apps assigned via groups
	// Note: group_members is a many-to-many table created by GORM
	var groupApps []domain.WebApp
	err = a.db.
		Joins("JOIN group_app_permission ON group_app_permission.app_id = web_app.id").
		Joins("JOIN group_members ON group_members.group_id = group_app_permission.group_id").
		Where("group_members.user_id = ? AND web_app.active = ?", userId, true).
		Find(&groupApps).Error
	if err != nil {
		// If group_members table doesn't exist yet, just return user apps
		// This can happen if groups haven't been used yet
		return apps, nil
	}
	
	// Merge and deduplicate
	appMap := make(map[string]domain.WebApp)
	for _, app := range apps {
		appMap[app.Id] = app
	}
	for _, app := range groupApps {
		if _, exists := appMap[app.Id]; !exists {
			appMap[app.Id] = app
		}
	}
	
	result := make([]domain.WebApp, 0, len(appMap))
	for _, app := range appMap {
		result = append(result, app)
	}
	
	return result, nil
}

func (a *appPers) Create(app domain.WebApp) (domain.WebApp, error) {
	err := a.db.Create(&app).Error
	return app, err
}

func (a *appPers) Update(app domain.WebApp) (domain.WebApp, error) {
	err := a.db.Save(&app).Error
	return app, err
}

func (a *appPers) Delete(id string) error {
	return a.db.Delete(&domain.WebApp{}, "id = ?", id).Error
}

