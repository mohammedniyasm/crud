package handler

import (
	"log/slog"
	"net/http"
	"usermanagement/internal/usecase"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

type Userhandler struct {
	usecase usecase.Userusecase
	logger  *slog.Logger
}

func NewUserhandler(uc *usecase.Userusecase, logg *slog.Logger) *Userhandler {
	return &Userhandler{
		usecase: *uc,
		logger:  logg,
	}
}
func (h *Userhandler) SignupPage(c *gin.Context) {
	c.HTML(200, "signup.html", nil)
}
func (h *Userhandler) LoginPage(c *gin.Context) {
	success := c.Query("success")
	c.HTML(200, "login.html", gin.H{
		"success": success,
	})
}
func (h *Userhandler) Signup(c *gin.Context) {
	name := c.PostForm("name")
	email := c.PostForm("email")
	password := c.PostForm("password")
	confirmPassword := c.PostForm("confirm_password")
	Input := usecase.SignupInput{
		Name:            name,
		Email:           email,
		Password:        password,
		ConfirmPassword: confirmPassword,
	}
	if err := h.usecase.Signup(Input); err != nil {
		c.HTML(400, "signup.html", gin.H{
			"error": err,
		})
		return
	}
	c.Redirect(302, "/login?success=1")
}
func (h *Userhandler) Login(c *gin.Context) {
	email := c.PostForm("email")
	password := c.PostForm("password")
	Input := usecase.LoginInput{
		Email:    email,
		Password: password,
	}
	user, err := h.usecase.Login(Input)
	if err != nil {
		c.HTML(200, "login.html", gin.H{
			"Email": email,
			"error": err,
		})
		return
	}
	session := sessions.DefaultMany(c, "user_session")
	session.Set("user_id", user.ID)
	session.Set("user_name", user.Name)
	if err := session.Save(); err != nil {
		h.logger.Error("login failed: session setting failed","user_id",user.ID,"error",err)
		c.HTML(500, "login.html", gin.H{
			"Email": email,
			"error": "Something went wrong",
		})
		return
	}
	c.Redirect(http.StatusFound, "/home")
}
func (h *Userhandler) Home(c *gin.Context) {
	userIDValue, _ := c.Get("user_id")
	userID := userIDValue.(uint)
	user, err := h.usecase.Home(userID)
	if err != nil {
		c.HTML(403, "login.html", gin.H{
			"error": err,
		})
		return
	}
	c.HTML(200, "home.html", gin.H{
		"name": user.Name,
	})
}
func (h *Userhandler) Logout(c *gin.Context) {
	session := sessions.DefaultMany(c, "user_session")
	userId:=session.Get("user_id")
	session.Clear()
	err := session.Save()
	if err != nil {
		h.logger.Error("logout failed: session saving failed","user_id",userId,"error",err)
		c.HTML(500, "home.html", gin.H{
			"error": "Unable to logout",
		})
		return
	}
	c.Redirect(302, "/login")
}
