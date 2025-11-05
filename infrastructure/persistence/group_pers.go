package persistence

import (
	"fmt"

	"github.com/labbs/bastion/domain"
	"gorm.io/gorm"
)

type groupPers struct {
	db *gorm.DB
}

func NewGroupPers(db *gorm.DB) *groupPers {
	return &groupPers{db: db}
}

func (g *groupPers) GetById(id string) (*domain.Group, error) {
	var group domain.Group
	err := g.db.Preload("Members").Where("id = ?", id).First(&group).Error
	if err == gorm.ErrRecordNotFound {
		return nil, fmt.Errorf("group not found")
	}
	return &group, err
}

func (g *groupPers) GetByName(name string) (*domain.Group, error) {
	var group domain.Group
	err := g.db.Preload("Members").Where("name = ?", name).First(&group).Error
	if err == gorm.ErrRecordNotFound {
		return nil, fmt.Errorf("group not found")
	}
	return &group, err
}

func (g *groupPers) GetAll() ([]domain.Group, error) {
	var groups []domain.Group
	err := g.db.Preload("Members").Find(&groups).Error
	return groups, err
}

func (g *groupPers) Create(group *domain.Group) error {
	return g.db.Create(group).Error
}

func (g *groupPers) Update(group *domain.Group) error {
	return g.db.Save(group).Error
}

func (g *groupPers) Delete(id string) error {
	return g.db.Delete(&domain.Group{}, "id = ?", id).Error
}

func (g *groupPers) AddMember(groupId, userId string) error {
	var group domain.Group
	if err := g.db.Where("id = ?", groupId).First(&group).Error; err != nil {
		return fmt.Errorf("group not found: %w", err)
	}

	var user domain.User
	if err := g.db.Where("id = ?", userId).First(&user).Error; err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	return g.db.Model(&group).Association("Members").Append(&user)
}

func (g *groupPers) RemoveMember(groupId, userId string) error {
	var group domain.Group
	if err := g.db.Where("id = ?", groupId).First(&group).Error; err != nil {
		return fmt.Errorf("group not found: %w", err)
	}

	var user domain.User
	if err := g.db.Where("id = ?", userId).First(&user).Error; err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	return g.db.Model(&group).Association("Members").Delete(&user)
}

func (g *groupPers) GetMembers(groupId string) ([]domain.User, error) {
	var group domain.Group
	if err := g.db.Where("id = ?", groupId).First(&group).Error; err != nil {
		return nil, fmt.Errorf("group not found: %w", err)
	}

	var members []domain.User
	err := g.db.Model(&group).Association("Members").Find(&members)
	return members, err
}
