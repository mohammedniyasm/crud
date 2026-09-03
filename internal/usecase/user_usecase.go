package usecase

import (
	"errors"
	"log/slog"
	"net/mail"
	"regexp"
	"unicode"
	"usermanagement/internal/domain"
	"usermanagement/internal/repository"

	"golang.org/x/crypto/bcrypt"
)

type SignupInput struct {
	Name            string
	Email           string
	Password        string
	ConfirmPassword string
}
type LoginInput struct {
	Email    string
	Password string
}
type Userusecase struct {
	repo   repository.UserRepository
	logger *slog.Logger
}

func NewUserusecase(repo repository.UserRepository, log *slog.Logger) *Userusecase {
	return &Userusecase{
		repo:   repo,
		logger: log,
	}
}
func (u *Userusecase) Signup(input SignupInput) error {
	if input.Name == "" || input.Email == "" || input.Password == "" || input.ConfirmPassword == "" {
		u.logger.Warn("signup validation failed: fields can't be empty", "email", input.Email)
		return errors.New("Field's can't be empty")
	}
	if !isStrongPassword(input.Password) {
		u.logger.Warn("signup validation failed: weak password", "email", input.Email)
		return errors.New("Password must contain at least 8 characters, one uppercase letter, one lowercase letter, one number, and one special character")
	}
	if input.Password != input.ConfirmPassword {
		u.logger.Warn("signup validation failed: password mismatch", "email", input.Email)
		return errors.New("Passwords must match")
	}
	if _, err := mail.ParseAddress(input.Email); err != nil {
		u.logger.Warn("signup validation failed: invalid email format", "email", input.Email)
		return errors.New("please enter a valid email address")
	}
	namePattern := regexp.MustCompile(`^[a-zA-Z ]+$`)
	if !namePattern.MatchString(input.Name) {
		u.logger.Warn("signup validation failed: invalid name", "email", input.Email)
		return errors.New("Name can only contain letters and spaces")
	}
	existinguser, err := u.repo.FindByEmail(input.Email)
	if err == nil && existinguser != nil {
		u.logger.Warn("signup validation failed: email already exists", "email", input.Email)
		return errors.New("Email already exists")
	}
	hashpassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		u.logger.Error("signup failed: password hashing failed", "email", input.Email, "error", err)
		return errors.New("Something Went Wrong")
	}
	newUser := &domain.User{
		Name:     input.Name,
		Email:    input.Email,
		Password: string(hashpassword),
		Role:     "user",
	}
	if err := u.repo.Create(newUser); err != nil {
		u.logger.Error("signup failed: user creation failed", "email", input.Email, "error", err)
		return errors.New("Unable to Create Account")
	}
	u.logger.Info("signup succefully completed", "email", input.Email)
	return nil
}
func (u *Userusecase) Login(input LoginInput) (*domain.User, error) {
	if input.Email == "" || input.Password == "" {
		u.logger.Warn("login validation failed: fields can't be empty", "email", input.Email)
		return nil, errors.New("Field's can't be empty")
	}
	if _, err := mail.ParseAddress(input.Email); err != nil {
		u.logger.Warn("login validation failed: invalid email address", "email", input.Email)
		return nil, errors.New("Please enter a valid email address")
	}
	user, err := u.repo.FindByEmail(input.Email)
	if err != nil && user == nil {
		u.logger.Warn("login validation failed: invalid credentials", "email", input.Email)
		return nil, errors.New("Invalid Credentials")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password)); err != nil {
		u.logger.Warn("login validation failed: invalid credentials", "email", input.Email)
		return nil, errors.New("Invalid Credentials")
	}
	if user.IsBlocked {
		u.logger.Warn("login failed: account has been blocked", "email", input.Email)
		return nil, errors.New("Your account has been Blocked")
	}
	u.logger.Info("login authentication completed", "user_id", user.ID)
	return user, nil
}
func (u *Userusecase) Home(id uint) (*domain.User, error) {
	user, err := u.repo.FindById(id)
	if err != nil {
		u.logger.Error("home access failed: user lookup failed","user_id", id,"error", err,)
		return nil, err
	}
	if user.IsBlocked {
		u.logger.Warn("home access denied: user is blocked","user_id", id,)
		return nil, errors.New("Your account has been blocked")
	}
	return user, nil
}
func isStrongPassword(password string) bool {
	if len(password) < 8 {
		return false
	}
	var hasUpper bool
	var hasLower bool
	var hasNumber bool
	var hasSpecial bool
	for _, ch := range password {
		switch {
		case unicode.IsUpper(ch):
			hasUpper = true
		case unicode.IsLower(ch):
			hasLower = true
		case unicode.IsNumber(ch):
			hasNumber = true
		case unicode.IsPunct(ch) || unicode.IsSymbol(ch):
			hasSpecial = true
		}
	}

	return hasUpper && hasLower && hasNumber && hasSpecial
}
