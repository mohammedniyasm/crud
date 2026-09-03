package postgres

import (
	"errors"
	"log/slog"
	"usermanagement/internal/domain"
	"usermanagement/internal/repository"

	"gorm.io/gorm"
)

type UserRepository struct {
	db     *gorm.DB
	logger *slog.Logger
}

func NewUserRepository(db *gorm.DB, log *slog.Logger) *UserRepository {
	return &UserRepository{
		db:     db,
		logger: log,
	}
}

func (u *UserRepository) Create(user *domain.User) error {
	if err := u.db.Create(user).Error; err != nil {
		u.logger.Error("failed to create user", "error", err)
		return err
	}
	u.logger.Info("user created", "user_id", user.ID)
	return nil
}
func (u *UserRepository) FindById(id uint) (*domain.User, error) {
	var user domain.User
	err := u.db.First(&user, id).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			u.logger.Debug("user not found", "user_id", id)
		} else {
			u.logger.Error("failed to fetch user", "user_id", id, "error", err)
		}
		return nil, err
	}
	u.logger.Debug("user fetched succefully", "user_id", id)
	return &user, nil
}
func (u *UserRepository) FindByEmail(email string) (*domain.User, error) {
	var user domain.User
	err := u.db.Where("email = ?", email).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			u.logger.Debug("user not found", "user_email", email)
		} else {
			u.logger.Error("failed to fetch user", "user_email", email, "error", err)
		}
		return nil, err
	}
	u.logger.Debug("user fetched succefully", "user_email", email)
	return &user, nil
}
func (u *UserRepository) FindAll() ([]domain.User, error) {
	var users []domain.User
	if err := u.db.Find(&users).Error; err != nil {
		u.logger.Error("users fetching failed", "error", err)
		return nil, err
	}
	u.logger.Debug("users fetched succefully")
	return users, nil
}
func (u *UserRepository) FindNormal() ([]domain.User, error) {
	var users []domain.User
	if err := u.db.Where("role NOT IN ?", []string{"admin", "superadmin"}).Find(&users).Error; err != nil {
		u.logger.Error("fetching normal users failed", "error", err)
		return nil, err
	}
	u.logger.Debug("fetched normal users succefully")
	return users, nil
}
func (u *UserRepository) Update(user *domain.User) error {
	if err := u.db.Updates(user).Error; err != nil {
		u.logger.Error("user updation failed", "user_id", user.ID, "error", err)
		return err
	}
	u.logger.Info("user updated succedully", "user_id", user.ID)
	return nil
}
func (u *UserRepository) Delete(id uint) error {
	if err := u.db.Delete(&domain.User{}, id).Error; err != nil {
		u.logger.Error("User deletion Failed", "user_id", id, "error", err)
		return err
	}
	u.logger.Info("user deleted succefully", "user_id", id)
	return nil
}
func (u *UserRepository) UpdateBlockStatus(id uint, isBlocked bool) error {
	if err := u.db.Model(&domain.User{}).Where("id = ?", id).Update("is_blocked", isBlocked).Error; err != nil {
		u.logger.Error("block status updation failed", "user_id", id, "error", err)
		return err
	}
	u.logger.Info("block status updated succefully", "user_id", id)
	return nil
}
func (u *UserRepository) ListNormalUsers(Option repository.UserListOptions) ([]domain.User, error) {
	var users []domain.User
	query := u.db.Where(
		"role NOT IN ?",
		[]string{"admin", "superadmin"},
	)
	if Option.Search != "" {
		query = query.Where("name ILIKE ? OR email ILIKE ?", "%"+Option.Search+"%", "%"+Option.Search+"%")
	}
	switch Option.Sort {
	case "az":
		query = query.Order("name ASC")
	case "za":
		query = query.Order("name DESC")
	case "old":
		query = query.Order("id DESC")
	case "new":
		query = query.Order("id ASC")
	default:
		query = query.Order("id DESC")
	}
	if err := query.Find(&users).Error; err != nil {
		u.logger.Error("listing normal users failed", "error", err)
		return nil, err
	}
	u.logger.Debug("succeffully listed normal users")
	return users, nil
}
func (u *UserRepository) ListAllUsers(Option repository.UserListOptions) ([]domain.User, error) {
	var users []domain.User
	query := u.db
	if Option.Search != "" {
		query = query.Where("name ILIKE ? OR email ILIKE ?", "%"+Option.Search+"%", "%"+Option.Search+"%")
	}
	switch Option.Sort {
	case "az":
		query = query.Order("name ASC")
	case "za":
		query = query.Order("name DESC")
	case "old":
		query = query.Order("id DESC")
	case "new":
		query = query.Order("id ASC")
	default:
		query = query.Order("id ASC")
	}
	if err := query.Find(&users).Error; err != nil {
		u.logger.Error("listing all users failed", "error", err)
		return nil, err
	}
	u.logger.Debug("succefully listed all users")
	return users, nil
}
func (u *UserRepository) FindByEmailExceptID(email string, id uint) (*domain.User, error) {
	var user domain.User
	err := u.db.
		Where("email = ? AND id != ?", email, id).
		First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			u.logger.Debug("no other user found with email", "email", email, "user_id", id)
		} else {
			u.logger.Error("database query failed", "user_id", id, "error", err)
		}
		return nil, err
	}
	u.logger.Debug("user found with existing email", "user_id", user.ID)
	return &user, nil
}
