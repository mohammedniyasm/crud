package usecase

import (
	"errors"
	"net/mail"
	"regexp"
	"unicode"
	"usermanagement/internal/domain"
	"usermanagement/internal/repository"

	"golang.org/x/crypto/bcrypt"
)
type SignupInput struct{
	Name string
	Email string
	Password string
	ConfirmPassword string
}
type LoginInput struct{
	Email string
	Password string
}
type Userusecase struct {
	repo repository.UserRepository
}
func NewUserusecase(repo repository.UserRepository)*Userusecase{
	return &Userusecase{
		repo: repo,
	}
}
func (u *Userusecase) Signup(input SignupInput) error{
	if input.Name==""||input.Email==""||input.Password==""||input.ConfirmPassword==""{
		return errors.New("Field's can't be empty")
	}
	if !isStrongPassword(input.Password){
		return errors.New("Password must contain at least 8 characters, one uppercase letter, one lowercase letter, one number, and one special character")
	}
	if input.Password != input.ConfirmPassword{
		return errors.New("Passwords must match")
	}
	if _, err := mail.ParseAddress(input.Email);err != nil{
		return errors.New("please enter a valid email address")
	}
	namePattern := regexp.MustCompile(`^[a-zA-Z ]+$`)
	if !namePattern.MatchString(input.Name) {
		return errors.New("Name can only contain letters and spaces")	
	}
	existinguser,err:=u.repo.FindByEmail(input.Email)
	if err == nil && existinguser != nil{
		return errors.New("Email already exists")
	}
	hashpassword,err:=bcrypt.GenerateFromPassword([]byte(input.Password),bcrypt.DefaultCost)
	if err != nil{
		return errors.New("Something Went Wrong")
	}
	newUser:=&domain.User{
		Name: input.Name,
		Email: input.Email,
		Password: string(hashpassword),
		Role: "user",
	}
	if err := u.repo.Create(newUser);err != nil{
		return errors.New("Unable to Create Account")
	}
	return nil
}
func (u *Userusecase) Login(input LoginInput) (*domain.User,error){
	if input.Email==""||input.Password==""{
		return nil,errors.New("Field's can't be empty")
	}
	if 	_, err := mail.ParseAddress(input.Email);err != nil{
		return nil,errors.New("Please enter a valid email address")
	}
	user,err:=u.repo.FindByEmail(input.Email)
	if err != nil && user == nil{
		return nil,errors.New("Invalid Credentials")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password),[]byte(input.Password));err != nil{
		return nil,errors.New("Invalid Credentials")
	}
	if user.IsBlocked {
		return nil,errors.New("Your account has been Blocked")
	}
	return user,nil
}
func (u *Userusecase) Home(id uint) (*domain.User,error){
	user,err:=u.repo.FindById(id)
	if err != nil{
		return nil,err
	}
	if user.IsBlocked{
		return nil,errors.New("Your account has been blocked")
	}
	return user,nil
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