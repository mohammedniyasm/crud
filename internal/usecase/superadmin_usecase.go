package usecase

import (
	"errors"
	"net/mail"
	"regexp"
	"usermanagement/internal/domain"
	"usermanagement/internal/repository"

	"golang.org/x/crypto/bcrypt"
)

type SuperAdminAdduser struct {
	Name            string
	Email           string
	Role            string
	Password        string
	ConfirmPassword string
}

func (u *Userusecase) GetSuperadminDashboardUsers(Input repository.UserListOptions) ([]domain.User, error) {
	users, err := u.repo.ListAllUsers(Input)
	if err != nil {
		u.logger.Error("failed to load superadmin dashboard users", "error", err)
		return nil, err
	}
	return users, nil
}
func (u *Userusecase) EditSuperAdmin(id uint, name string, email string, role string) error {
	user, err := u.repo.FindById(id)
	if err != nil {
		return errors.New("User not found")
	}
	if user.ID == 1 && user.Role == "superadmin" {
		u.logger.Warn("superadmin edit operation failed: primary superadmin can't be edit", "user_id", id)
		return errors.New("Primary superadmin Can't be edited")
	}
	existingUser, err := u.repo.FindByEmailExceptID(email, id)
	if err == nil && existingUser != nil {
		return errors.New("Email already exists")
	}
	user.Name = name
	user.Email = email
	user.Role = role
	if err := u.repo.Update(user); err != nil {
		return errors.New("Unable to Edit user")
	}
	return nil
}
func (u *Userusecase) AddSuperAdmin(input SuperAdminAdduser) error {
	if input.Name == "" || input.Email == "" || input.Password == "" || input.ConfirmPassword == "" {
		u.logger.Warn("superadmin user add operation failed: fields can't be empty", "email", input.Email)
		return errors.New("Field's Can't be empty")
	}
	if !isStrongPassword(input.Password) {
		u.logger.Warn("superadmin user add operation failed: weak password", "email", input.Email)
		return errors.New("Password must contain at least 8 characters, one uppercase letter, one lowercase letter, one number, and one special character")
	}
	if input.Password != input.ConfirmPassword {
		u.logger.Warn("superadmin user add operation failed: password mismatch", "email", input.Email)
		return errors.New("Passwords must be match")
	}
	_, err := mail.ParseAddress(input.Email)
	if err != nil {
		u.logger.Warn("superadmin user add operation failed: invalid email format", "email", input.Email)
		return errors.New("Please Enter a valid email address")
	}
	namePattern := regexp.MustCompile(`^[a-zA-Z ]+$`)
	if !namePattern.MatchString(input.Name) {
		u.logger.Warn("superadmin user add operation failed: invalid name", "email", input.Email)
		return errors.New("Name can only contain letters and spaces")
	}
	existinguser, err := u.repo.FindByEmail(input.Email)
	if err == nil && existinguser != nil {
		u.logger.Warn("superadmin user add operation failed: user already exists", "email", input.Email)
		return errors.New("Email already exists")
	}
	hashpassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		u.logger.Error("superadmin user add operation failed: password hashing Failed", "email", input.Email)
		return errors.New("Something Went Wrong")
	}
	newUser := &domain.User{
		Name:     input.Name,
		Email:    input.Email,
		Password: string(hashpassword),
		Role:     input.Role,
	}
	if err := u.repo.Create(newUser); err != nil {
		return errors.New("Unable to Create Account")
	}
	u.logger.Info("superadmin user add operation succefully completed", "email", input.Email)
	return nil
}
