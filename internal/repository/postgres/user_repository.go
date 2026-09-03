package postgres

import (
	"usermanagement/internal/domain"
	"usermanagement/internal/repository"

	"gorm.io/gorm"
)

type UserRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{
		db: db,
	}
}

func (u *UserRepository) Create(user *domain.User) error {
	return u.db.Create(user).Error
}
func (u *UserRepository) FindById(id uint) (*domain.User, error) {
	var user domain.User
	err := u.db.First(&user, id).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}
func (u *UserRepository) FindByEmail(email string) (*domain.User, error) {
	var user domain.User
	err := u.db.Where("email = ?", email).First(&user).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}
func (u *UserRepository) FindAll() ([]domain.User, error) {
	var users []domain.User
	if err := u.db.Find(users).Error; err != nil {
		return nil, err
	}
	return users, nil
}
func (u *UserRepository) FindNormal() ([]domain.User, error) {
	var users []domain.User
	if err := u.db.Where("role NOT IN ?",[]string{"admin","superadmin"}).Find(users).Error; err != nil {
		return nil, err
	}
	return users, nil
}
func (u *UserRepository) Update(user *domain.User) error {
	return u.db.Updates(user).Error
}
func (u *UserRepository) Delete(id uint) error {
	return u.db.Delete(&domain.User{}, id).Error
}
func (u *UserRepository) UpdateBlockStatus(id uint, isBlocked bool) error {
	return u.db.Model(&domain.User{}).Where("id = ?", id).Update("Is_blocked", isBlocked).Error
}
func (u *UserRepository) ListNormalUsers(Option repository.UserListOptions) ([]domain.User, error) {
	var users []domain.User
	query:=u.db.Where(
		"role NOT IN ?",
		[]string{"admin","superadmin"},
	)
	if Option.Search != ""{
		query=query.Where("name ILIKE ? OR email ILIKE ?","%"+Option.Search+"%","%"+Option.Search+"%")
	}
	switch Option.Sort{
	case "az":
		query=query.Order("name ASC")
	case "za":
		query=query.Order("name DESC")
	case "old":
		query=query.Order("id DESC")
	case "new":
		query=query.Order("id ASC")
	default :
		query=query.Order("id DESC")
	}
	if err:=query.Find(&users).Error;err !=nil{
		return nil,err
	}
	return users, nil
}
func (u *UserRepository) ListAllUsers(Option repository.UserListOptions) ([]domain.User, error) {
	var users []domain.User
	query:=u.db
	if Option.Search != ""{
		query=query.Where("name ILIKE ? OR email ILIKE ?","%"+Option.Search+"%","%"+Option.Search+"%")
	}
	switch Option.Sort{
	case "az":
		query=query.Order("name ASC")
	case "za":
		query=query.Order("name DESC")
	case "old":
		query=query.Order("id DESC")
	case "new":
		query=query.Order("id ASC")
	default :
		query=query.Order("id ASC")
	}
	if err:=query.Find(&users).Error;err !=nil{
		return nil,err
	}
	return users, nil
}
func (u *UserRepository) FindByEmailExceptID(email string, id uint) (*domain.User, error) {
	var user domain.User

	err := u.db.
		Where("email = ? AND id != ?", email, id).
		First(&user).Error

	if err != nil {
		return nil, err
	}

	return &user, nil
}