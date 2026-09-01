package handlers

import (
	"errors"
	"net/http"
	"net/mail"
	"regexp"
	"unicode"
	"usermanagement/database"
	"usermanagement/models"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func Home(c *gin.Context) {
	session := sessions.DefaultMany(c, "user_session")
	userId := session.Get("user_id")
	userName := session.Get("user_name")
	if userId == nil {
		c.Redirect(302, "/login")
		return
	}
	var user models.User
	res := database.DB.Where("id = ?", userId).First(&user)
	if res.Error != nil {
		c.HTML(200, "login.html", gin.H{
			"error": "Something Went Wrong",
		})
		return
	}
	if user.IsBlocked {
		c.HTML(200, "login.html", gin.H{
			"error": "Your Account has been Blocked",
		})
		return
	}
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
	c.Redirect(302, "/home")
}
func Signup(c *gin.Context) {
	name := c.PostForm("name")
	email := c.PostForm("email")
	password := c.PostForm("password")
	confirmPassword := c.PostForm("confirm_password")
	if !isStrongPassword(password) {
		c.HTML(http.StatusBadRequest, "signup.html", gin.H{
			"Name":  name,
			"Email": email,
			"error": "Password must contain at least 8 characters, one uppercase letter, one lowercase letter, one number, and one special character",
		})
		return
	}
	if name == "" || email == "" || password == "" || confirmPassword == "" {
		c.HTML(200, "signup.html", gin.H{
			"Name":  name,
			"Email": email,
			"error": "Fields can't be empty",
		})
		return
	} else if password != confirmPassword {
		c.HTML(200, "signup.html", gin.H{
			"Name":  name,
			"Email": email,
			"error": "Passwords must match",
		})
		return
	}
	_, err := mail.ParseAddress(email)
	if err != nil {
		c.HTML(200, "signup.html", gin.H{
			"Name":  name,
			"Email": email,
			"error": "Please enter a valid email address",
		})
		return
	}
	namePattern := regexp.MustCompile(`^[a-zA-Z ]+$`)
	if !namePattern.MatchString(name) {
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
			c.HTML(200, "signup.html", gin.H{
				"Name":  name,
				"Email": email,
				"error": "Unable to create account",
			})
			return
		}
		c.Redirect(http.StatusSeeOther, "/login?success=1")
	} else if result.Error != nil {
		c.HTML(200, "signup.html", gin.H{
			"Name":  name,
			"Email": email,
			"error": "Something Went wrong",
		})
		return
	} else {
		c.HTML(200, "signup.html", gin.H{
			"Name":  name,
			"Email": email,
			"error": "Email already Exists",
		})
		return
	}
}

//	func Login(c *gin.Context) {
//			email := c.PostForm("email")
//			password := c.PostForm("password")
//			if email == "" || password == "" {
//				c.HTML(200, "login.html", gin.H{
//					"error": "Fields can't be empty",
//				})
//				return
//			}
//			var user models.User
//			result := database.DB.Where("email = ?", email).First(&user)
//			if errors.Is(result.Error, gorm.ErrRecordNotFound) {
//				c.HTML(200, "login.html", gin.H{
//					"error": "Invalid Credentials",
//				})
//			} else if result.Error != nil {
//				c.HTML(200, "login.html", gin.H{
//					"error": "Something Went wrong",
//				})
//			} else {
//				res := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
//				if res != nil {
//					c.HTML(200, "login.html", gin.H{
//						"error": "Invalid Credentials",
//					})
//					return
//				}
//				session := sessions.Default(c)
//				session.Set("user_id", user.ID)
//				session.Set("user_name", user.Name)
//				err := session.Save()
//				if err != nil {
//					c.HTML(200, "login.html", gin.H{
//						"error": "Something went wrong",
//					})
//				}
//				c.Redirect(302, "/home")
//			}
//	}
func Login(c *gin.Context) {
	email := c.PostForm("email")
	password := c.PostForm("password")
	if email == "" || password == "" {
		c.HTML(200, "login.html", gin.H{
			"Email": email,
			"error": "Fields can't be empty",
		})
		return
	}
	_, err := mail.ParseAddress(email)
	if err != nil {
		c.HTML(200, "login.html", gin.H{
			"Email": email,
			"error": "Please enter a valid email address",
		})
		return
	}
	var user models.User
	result := database.DB.Where("email = ?", email).First(&user)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		c.HTML(200, "login.html", gin.H{
			"Email": email,
			"error": "Invalid Credentials",
		})
	} else if result.Error != nil {
		c.HTML(200, "login.html", gin.H{
			"Email": email,
			"error": "Something Went wrong",
		})
	} else {
		res := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
		if res != nil {
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
			c.HTML(200, "login.html", gin.H{
				"Email": email,
				"error": "Something went wrong",
			})
		}
		c.Redirect(302, "/home")
	}
}
func Logout(c *gin.Context) {
	session := sessions.DefaultMany(c, "user_session")
	session.Delete("user_id")
	session.Delete("user_name")
	err := session.Save()
	if err != nil {
		c.HTML(200, "home.html", gin.H{
			"error": "Unable to logout",
		})
		return
	}
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
