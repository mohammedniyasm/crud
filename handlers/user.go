package handlers

import (
	"errors"
	"net/http"
	"net/mail"
	"os/user"
	"regexp"
	"unicode"
	"usermanagement/database"
	"usermanagement/logger"
	"usermanagement/models"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)
var Logger = logger.NewLogger()
func Home(c *gin.Context) {
	session := sessions.DefaultMany(c, "user_session")
	userId := session.Get("user_id")
	userName := session.Get("user_name")
	if userId == nil {
		Logger.Warn("Unauthorized access to home page - redirecting to login")
		c.Redirect(302, "/login")
		return
	}
	var user models.User
	res := database.DB.Where("id = ?", userId).First(&user)
	if res.Error != nil {
		Logger.Error("Database Query Failed on Home page","user_id",userId,"Error",res.Error)
		c.HTML(200, "login.html", gin.H{
			"error": "Something Went Wrong",
		})
		return
	}
	if user.IsBlocked {
		Logger.Warn("User account Blocked","user_id",userId,"email",user.Email)
		c.HTML(200, "login.html", gin.H{
			"error": "Your Account has been Blocked",
		})
		return
	}
	Logger.Info("User Accesed homepage","user_id",userId,"user_email",user.Email)
	c.HTML(200, "home.html", gin.H{
		"name": userName,
	})
}
func Signuppage(c *gin.Context) {
	session := sessions.DefaultMany(c, "user_session")
	userId := session.Get("user_id")
	if userId == nil {
		c.HTML(200, "signup.html", nil)
		return
	}
	Logger.Debug("Authenticated user redirected to home page","user_id",userId)
	c.Redirect(302, "/home")
}
func Loginpage(c *gin.Context) {
	session := sessions.DefaultMany(c, "user_session")
	userId := session.Get("user_id")
	if userId == nil {
		success := c.Query("success")
		c.HTML(200, "login.html", gin.H{
			"success": success,
		})
		return
	}
	Logger.Debug("Authenticated user redirected to home page","user_id",userId)
	c.Redirect(302, "/home")
}
func Signup(c *gin.Context) {
	name := c.PostForm("name")
	email := c.PostForm("email")
	password := c.PostForm("password")
	confirmPassword := c.PostForm("confirm_password")
	if !isStrongPassword(password) {
		Logger.Warn("Signup validation Failed: weak password","email",email)
		c.HTML(http.StatusBadRequest, "signup.html", gin.H{
			"Name":  name,
			"Email": email,
			"error": "Password must contain at least 8 characters, one uppercase letter, one lowercase letter, one number, and one special character",
		})
		return
	}
	if name == "" || email == "" || password == "" || confirmPassword == "" {
		Logger.Warn("Signup validation failed: empty field","name",name,"email",email)
		c.HTML(200, "signup.html", gin.H{
			"Name":  name,
			"Email": email,
			"error": "Fields can't be empty",
		})
		return
	} else if password != confirmPassword {
		Logger.Warn("Signup validation failed: password mismatch","email",email)
		c.HTML(200, "signup.html", gin.H{
			"Name":  name,
			"Email": email,
			"error": "Passwords must match",
		})
		return
	}
	_, err := mail.ParseAddress(email)
	if err != nil {
		Logger.Warn("Signup Validation failed: invalid email format","email",email)
		c.HTML(200, "signup.html", gin.H{
			"Name":  name,
			"Email": email,
			"error": "Please enter a valid email address",
		})
		return
	}
	namePattern := regexp.MustCompile(`^[a-zA-Z ]+$`)
	if !namePattern.MatchString(name) {
		Logger.Warn("Signup Validation Failed: Invalid name","email",email)
		c.HTML(200, "signup.html", gin.H{
			"Name":  name,
			"Email": email,
			"error": "Name can only contain letters and spaces",
		})
		return
	}
	var existingUser models.User
	result := database.DB.Where("email = ?", email).First(&existingUser)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		hashpassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			Logger.Error("Signup error: hashing password failed","email",email,"Error",err)
			c.HTML(200, "signup.html", gin.H{
				"Name":  name,
				"Email": email,
				"error": "Something Went Wrong",
			})
			return
		}
		newUser := models.User{
			Name:     name,
			Email:    email,
			Password: string(hashpassword),
		}
		result = database.DB.Create(&newUser)
		if result.Error != nil {
			Logger.Error("Signup error: User creation Failed","email",email,"Error",result.Error)
			c.HTML(200, "signup.html", gin.H{
				"Name":  name,
				"Email": email,
				"error": "Unable to create account",
			})
			return
		}
		Logger.Info("User created Succefully","email",email)
		c.Redirect(http.StatusSeeOther, "/login?success=1")
	} else if result.Error != nil {
		Logger.Error("Signup Error","email",email,"error",result.Error)
		c.HTML(200, "signup.html", gin.H{
			"Name":  name,
			"Email": email,
			"error": "Something Went wrong",
		})
		return
	} else {
		Logger.Warn("Signup Error: Email already existing","email",email)
		c.HTML(200, "signup.html", gin.H{
			"Name":  name,
			"Email": email,
			"error": "Email already Exists",
		})
		return
	}
}
func Login(c *gin.Context) {
	email := c.PostForm("email")
	password := c.PostForm("password")
	if email == "" || password == "" {
		Logger.Warn("Login validation Failed: invalid Fields","email",email)
		c.HTML(200, "login.html", gin.H{
			"Email": email,
			"error": "Fields can't be empty",
		})
		return
	}
	_, err := mail.ParseAddress(email)
	if err != nil {
		Logger.Warn("Login Validation Failed: invalid email format","email",email)
		c.HTML(200, "login.html", gin.H{
			"Email": email,
			"error": "Please enter a valid email address",
		})
		return
	}
	var user models.User
	result := database.DB.Where("email = ?", email).First(&user)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		Logger.Warn("Login Error : Email not found","email",email)
		c.HTML(200, "login.html", gin.H{
			"Email": email,
			"error": "Invalid Credentials",
		})
	} else if result.Error != nil {
		Logger.Error("Login Error :","email",email,"error",result.Error)
		c.HTML(200, "login.html", gin.H{
			"Email": email,
			"error": "Something Went wrong",
		})
	} else {
		res := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
		if res != nil {
			Logger.Error("Login Error: invalid Credentials","email",email)
			c.HTML(200, "login.html", gin.H{
				"Email": email,
				"error": "Invalid Credentials",
			})
			return
		}
		session := sessions.DefaultMany(c, "user_session")
		session.Set("user_id", user.ID)
		session.Set("user_name", user.Name)
		err := session.Save()
		if err != nil {
			Logger.Error("Login Error: session setting failed","email",email,"error",err)
			c.HTML(200, "login.html", gin.H{
				"Email": email,
				"error": "Something went wrong",
			})
			return
		}
		Logger.Info("User Logined succefully","user_id",user.ID,"email",email)
		c.Redirect(302, "/home")
	}
}
func Logout(c *gin.Context) {
	session := sessions.DefaultMany(c, "user_session")
	userId:=session.Get("user_id")
	session.Delete("user_id")
	session.Delete("user_name")
	err := session.Save()
	if err != nil {
		Logger.Error("Logout Error: session save Failed","user_id",userId,"error",err)
		c.HTML(200, "home.html", gin.H{
			"error": "Unable to logout",
		})
		return
	}
	Logger.Info("User logged out succefully","user_id",userId)
	c.Redirect(302, "/login")
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
