package domain

import "time"

type Group struct {
	Id          string
	Name        string
	Description string

	Role Role `gorm:"type:role;default:'user'"`

	// Owner is the username of the user who owns the group
	OwnerId string
	// OwnerUser is the user who owns the group
	OwnerUser User `gorm:"foreignKey:OwnerId;references:Id"`

	// Members is the list of users who are members of the group
	Members []User `gorm:"many2many:group_members;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`

	CreatedAt time.Time
	UpdatedAt time.Time
}

func (g *Group) TableName() string {
	return "group"
}

type GroupPers interface {
	GetById(id string) (*Group, error)
	GetByName(name string) (*Group, error)
	GetAll() ([]Group, error)
	Create(group *Group) error
	Update(group *Group) error
	Delete(id string) error
	AddMember(groupId, userId string) error
	RemoveMember(groupId, userId string) error
	GetMembers(groupId string) ([]User, error)
}
