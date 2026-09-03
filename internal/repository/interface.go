package repository

import (
	"usermanagement/internal/domain"
)

type UserListOptions struct {
	Search string
	Sort   string
}

type UserRepository interface {
	Create(user *domain.User) error

	FindById(id uint) (*domain.User, error)
	FindByEmail(email string) (*domain.User, error)
	FindAll() ([]domain.User, error)
	FindNormal() ([]domain.User, error)
	FindByEmailExceptID(email string, id uint) (*domain.User, error)

	Update(user *domain.User) error
	Delete(id uint) error

	UpdateBlockStatus(id uint, isBlocked bool) error

	ListNormalUsers(Option UserListOptions) ([]domain.User, error)
	ListAllUsers(Option UserListOptions) ([]domain.User, error)
}
