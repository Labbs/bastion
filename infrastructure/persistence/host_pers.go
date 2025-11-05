package persistence

import (
	"github.com/labbs/bastion/domain"
	"gorm.io/gorm"
)

type hostPers struct {
	db *gorm.DB
}

func NewHostPers(db *gorm.DB) *hostPers {
	return &hostPers{db: db}
}

func (h *hostPers) GetById(id string) (domain.Host, error) {
	var host domain.Host
	err := h.db.Where("id = ?", id).First(&host).Error
	return host, err
}

func (h *hostPers) GetAll() ([]domain.Host, error) {
	var hosts []domain.Host
	err := h.db.Where("active = ?", true).Find(&hosts).Error
	return hosts, err
}

func (h *hostPers) GetByUserId(userId string) ([]domain.Host, error) {
	var hosts []domain.Host
	err := h.db.
		Joins("JOIN user_host_permission ON user_host_permission.host_id = host.id").
		Where("user_host_permission.user_id = ? AND host.active = ?", userId, true).
		Find(&hosts).Error
	return hosts, err
}

func (h *hostPers) Create(host domain.Host) (domain.Host, error) {
	err := h.db.Create(&host).Error
	return host, err
}

func (h *hostPers) Update(host domain.Host) (domain.Host, error) {
	err := h.db.Save(&host).Error
	return host, err
}

func (h *hostPers) Delete(id string) error {
	return h.db.Delete(&domain.Host{}, "id = ?", id).Error
}

