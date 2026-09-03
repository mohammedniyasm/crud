package usecase

import (
	"errors"
	"net/mail"
	"regexp"
	"usermanagement/internal/domain"
	"usermanagement/internal/repository"

	"golang.org/x/crypto/bcrypt"
)

func (u *Userusecase) AdminLogin(input LoginInput) (*domain.User, error) {
	if input.Email == "" || input.Password == "" {
		u.logger.Warn("admin login validation failed", "reason", "empty fields")
		return nil, errors.New("Field's can't be empty")
	}
	if _, err := mail.ParseAddress(input.Email); err != nil {
		u.logger.Warn("admin login validation failed", "reason", "invalid email")
		return nil, errors.New("Please enter a valid email address")
	}
	user, err := u.repo.FindByEmail(input.Email)
	if err != nil && user == nil {
		u.logger.Warn("admin login validation failed", "reason", "invalid credentials")
		return nil, errors.New("Invalid Credentials")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password)); err != nil {
		u.logger.Warn("admin login validation failed", "reason", "invalid credentials")
		return nil, errors.New("Invalid Credentials")
	}
	if user.IsBlocked {
		u.logger.Warn("admin login validation failed", "reason", "account blocked")
		return nil, errors.New("Your account has been Blocked")
	}
	if user.Role != "admin" && user.Role != "superadmin" {
		u.logger.Warn("admin login validation failed", "reason", "user not authorized")
		return nil, errors.New("You are not authorized person")
	}
	u.logger.Info("admin login authentication completed", "user_id", user.ID)
	return user, nil
}
func (u *Userusecase) GetAdminDashboardUsers(Input repository.UserListOptions) ([]domain.User, error) {
	users, err := u.repo.ListNormalUsers(Input)
	if err != nil {
		u.logger.Error("failed to load admin dashboard users", "error", err)
		return nil, err
	}

	return users, nil
}
func (u *Userusecase) BlockAdmin(targetId uint) error {
	user, err := u.repo.FindById(targetId)
	if err != nil {
		return errors.New("User not found")
	}
	if user.ID == 1 && user.Role == "superadmin" {
		u.logger.Warn("admin block operation failed: primary admin can't be blocked", "user_id", targetId)
		return errors.New("Primary superadmin Can't be edited")
	}
	newBlockedStatus := !user.IsBlocked
	if err := u.repo.UpdateBlockStatus(targetId, newBlockedStatus); err != nil {
		return errors.New("Unable to update user")
	}
	return nil
}
func (u *Userusecase) EditAdmin(id uint, name string, email string) error {
	user, err := u.repo.FindById(id)
	if err != nil {
		return errors.New("User not found")
	}
	if user.ID == 1 && user.Role == "superadmin" {
		u.logger.Warn("admin edit operaion failed: primary admin can't be edited", "user_id", id)
		return errors.New("Primary superadmin Can't be edited")
	}
	existingUser, err := u.repo.FindByEmailExceptID(email, id)
	if err == nil && existingUser != nil {
		u.logger.Warn("admin edit operaion failed: email already exists", "user_id", id)
		return errors.New("Email already exists")
	}
	user.Name = name
	user.Email = email
	if err := u.repo.Update(user); err != nil {
		return errors.New("Unable to Edit user")
	}
	return nil
}
func (u *Userusecase) DeleteAdmin(targetId uint) error {
	user, err := u.repo.FindById(targetId)
	if err != nil {
		return errors.New("User not found")
	}
	if user.ID == 1 && user.Role == "superadmin" {
		u.logger.Warn("admin delete operation failed: primary admin can't be edit or delete", "user_id", targetId)
		return errors.New("Primary superadmin Can't be edited")
	}
	if err := u.repo.Delete(targetId); err != nil {
		return errors.New("Unable to update user")
	}
	return nil
}
func (u *Userusecase) AddAdmin(input SignupInput) error {
	if input.Name == "" || input.Email == "" || input.Password == "" || input.ConfirmPassword == "" {
		u.logger.Warn("admin user add operation failed: fields can't be empty", "email", input.Email)
		return errors.New("Field's Can't be empty")
	}
	if !isStrongPassword(input.Password) {
		u.logger.Warn("admin user add operation failed: weak password", "email", input.Email)
		return errors.New("Password must contain at least 8 characters, one uppercase letter, one lowercase letter, one number, and one special character")
	}
	if input.Password != input.ConfirmPassword {
		u.logger.Warn("admin user add operation failed: password mismatch", "email", input.Email)
		return errors.New("Passwords must be match")
	}
	_, err := mail.ParseAddress(input.Email)
	if err != nil {
		u.logger.Warn("admin user add operation failed: invalid email address", "email", input.Email)
		return errors.New("Please Enter a valid email address")
	}
	namePattern := regexp.MustCompile(`^[a-zA-Z ]+$`)
	if !namePattern.MatchString(input.Name) {
		u.logger.Warn("admin user add operation failed: invalid name", "email", input.Email)
		return errors.New("Name can only contain letters and spaces")
	}
	existinguser, err := u.repo.FindByEmail(input.Email)
	if err == nil && existinguser != nil {
		u.logger.Warn("admin user add operation failed: user already exists", "email", input.Email)
		return errors.New("Email already exists")
	}
	hashpassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		u.logger.Error("admin user add operation failed: password hashing Failed", "email", input.Email)
		return errors.New("Something Went Wrong")
	}
	newUser := &domain.User{
		Name:     input.Name,
		Email:    input.Email,
		Password: string(hashpassword),
		Role:     "user",
	}
	if err := u.repo.Create(newUser); err != nil {
		return errors.New("Unable to Create Account")
	}
	u.logger.Info("admin user add operation succefully completed", "email", input.Email)
	return nil
}
