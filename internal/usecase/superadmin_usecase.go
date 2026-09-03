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
	return u.repo.ListAllUsers(Input)
}
func (u *Userusecase) EditSuperAdmin(id uint, name string, email string, role string) error {
	user, err := u.repo.FindById(id)
	if err != nil {
		return errors.New("User not found")
	}
	if user.ID == 1 && user.Role == "superadmin" {
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
		return errors.New("Field's Can't be empty")
	}
	if !isStrongPassword(input.Password) {
		return errors.New("Password must contain at least 8 characters, one uppercase letter, one lowercase letter, one number, and one special character")
	}
	if input.Password != input.ConfirmPassword {
		return errors.New("Passwords must be match")
	}
	_, err := mail.ParseAddress(input.Email)
	if err != nil {
		return errors.New("Please Enter a valid email address")
	}
	namePattern := regexp.MustCompile(`^[a-zA-Z ]+$`)
	if !namePattern.MatchString(input.Name) {
		return errors.New("Name can only contain letters and spaces")
	}
	existinguser, err := u.repo.FindByEmail(input.Email)
	if err == nil && existinguser != nil {
		return errors.New("Email already exists")
	}
	hashpassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
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
	return nil
}
