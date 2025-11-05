package persistence

import (
	"github.com/labbs/bastion/domain"
	"gorm.io/gorm"
)

type userPers struct {
	db *gorm.DB
}

func NewUserPers(db *gorm.DB) *userPers {
	return &userPers{db: db}
}

func (u *userPers) GetByUsername(username string) (domain.User, error) {
	var user domain.User
	err := u.db.Debug().Where("username = ?", username).First(&user).Error
	return user, err
}

func (u *userPers) GetByEmail(email string) (domain.User, error) {
	var user domain.User
	err := u.db.Debug().Where("email = ?", email).First(&user).Error
	return user, err
}

func (u *userPers) Create(user domain.User) (domain.User, error) {
	err := u.db.Create(&user).Error
	return user, err
}

func (u *userPers) GetById(id string) (domain.User, error) {
	var user domain.User
	err := u.db.Debug().Where("id = ?", id).First(&user).Error
	return user, err
}

func (u *userPers) GetAll() ([]domain.User, error) {
	var users []domain.User
	err := u.db.Find(&users).Error
	return users, err
}

func (u *userPers) Update(user domain.User) (domain.User, error) {
	err := u.db.Save(&user).Error
	return user, err
}

func (u *userPers) Delete(id string) error {
	return u.db.Delete(&domain.User{}, "id = ?", id).Error
}
