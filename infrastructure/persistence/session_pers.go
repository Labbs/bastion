package persistence

import (
	"github.com/labbs/bastion/domain"
	"gorm.io/gorm"
)

type sessionPers struct {
	db *gorm.DB
}

func NewSessionPers(db *gorm.DB) *sessionPers {
	return &sessionPers{db: db}
}

func (s *sessionPers) Create(session *domain.Session) error {
	return s.db.Create(session).Error
}

func (s *sessionPers) GetById(id string) (*domain.Session, error) {
	var session domain.Session
	err := s.db.Where("id = ?", id).First(&session).Error
	if err != nil {
		return nil, err
	}
	return &session, nil
}

func (s *sessionPers) DeleteById(id string) error {
	return s.db.Where("id = ?", id).Delete(&domain.Session{}).Error
}
