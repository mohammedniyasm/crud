package handler

import (
	"strconv"
	"usermanagement/internal/domain"
	"usermanagement/internal/repository"
	"usermanagement/internal/usecase"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

//common
func (h *Userhandler) AdminLoginPage(c *gin.Context) {
	session := sessions.DefaultMany(c, "admin_session")
	authError := session.Get("auth_error")
	session.Delete("auth_error")
	_ = session.Save()
	c.HTML(200, "admin-login.html", gin.H{
		"error": authError,
	})
}
func (h *Userhandler) AdminLogin(c *gin.Context) {
	email := c.PostForm("email")
	password := c.PostForm("password")
	Input := usecase.LoginInput{
		Email:    email,
		Password: password,
	}
	user, err := h.usecase.AdminLogin(Input)
	if err != nil {
		c.HTML(200, "admin-login.html", gin.H{
			"Email": email,
			"error": err,
		})
		return
	}
	session := sessions.DefaultMany(c, "admin_session")
	session.Set("admin_id", user.ID)
	session.Set("admin_name", user.Name)
	session.Set("role", user.Role)
	if err := session.Save(); err != nil {
		h.logger.Error("admin login failed: session saving failed","user_id",user.ID,"error",err.Error())
		c.HTML(500, "admin-login.html", gin.H{
			"Email": email,
			"error": "Something went wrong",
		})
		return
	}
	switch user.Role {
	case "admin":
		c.Redirect(302, "/admin/dashboard")
	case "superadmin":
		c.Redirect(302, "/superadmin/dashboard")
	}
}

//admin handlers
func (h *Userhandler) AdminLogout(c *gin.Context) {
	session := sessions.DefaultMany(c, "admin_session")
	userid:=session.Get("admin_id")
	session.Clear()
	if err := session.Save(); err != nil {
		h.logger.Error("admin logout failed: session saving failed","user_id",userid,"error",err.Error())
		c.HTML(500, "admin-dashboard.html", gin.H{
			"error": "Unable to logout",
		})
		return
	}
	c.Redirect(302, "/admin/login")
}
func (h *Userhandler) AdminDashboard(c *gin.Context) {
	session:=sessions.DefaultMany(c,"admin_session")
	errormessage:=session.Get("error")
	session.Delete("error")
	_=session.Save()
	AdminValue, _ := c.Get("admin_value")
	admin := AdminValue.(*domain.User)
	sort := c.Query("sort")
	search := c.Query("search")
	users, err := h.usecase.GetAdminDashboardUsers(repository.UserListOptions{
		Search: search,
		Sort:   sort,
	})
	if err != nil {
		c.HTML(500, "admin-dashboard.html", gin.H{
			"error": "something went wrong",
		})
		return
	}
	c.HTML(200, "admin-dashboard.html", gin.H{
		"admin": admin,
		"users": users,
		"error":errormessage,
	})
}
func (h *Userhandler) AdminBlock(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.Redirect(302, "/admin/dashboard")
		return
	}
	targetUserid := uint(id)
	if err := h.usecase.BlockAdmin(targetUserid); err != nil {
		session := sessions.DefaultMany(c, "admin_session")
		session.Set("error", err)
		if errr := session.Save(); errr != nil {
			h.logger.Error("admin block operation failed: session saving failed","user_id",targetUserid,"error",err.Error())
			c.AbortWithStatus(500)
			return
		}
		c.Redirect(302, "/admin/dashboard")
		return
	}
	c.Redirect(302, "/admin/dashboard")
}
func (h *Userhandler) AdminEdit(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.Redirect(302, "/admin/dashboard")
		return
	}
	targetUserid := uint(id)
	name := c.PostForm("name")
	email := c.PostForm("email")

	if err := h.usecase.EditAdmin(targetUserid,name,email); err != nil {
		session := sessions.DefaultMany(c, "admin_session")
		session.Set("error", err.Error())
		if errr := session.Save(); errr != nil {
			h.logger.Error("admin edit operation failed: session saving failed","user_id",targetUserid,"error",err.Error())
			c.AbortWithStatus(500)
			return
		}
		c.Redirect(302, "/admin/dashboard")
		return
	}
	c.Redirect(302, "/admin/dashboard")
}
func (h *Userhandler) AdminDelete(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.Redirect(302, "/admin/dashboard")
		return
	}
	targetUserid := uint(id)
	if err := h.usecase.DeleteAdmin(targetUserid); err != nil {
		session := sessions.DefaultMany(c, "admin_session")
		session.Set("error", err)
		if errr := session.Save(); errr != nil {
			h.logger.Error("admin delete operation failed: session saving failed","user_id",targetUserid,"error",err.Error())
			c.AbortWithStatus(500)
			return
		}
		c.Redirect(302, "/admin/dashboard")
		return
	}
	c.Redirect(302, "/admin/dashboard")
}
func (h *Userhandler) AdminAddUser(c *gin.Context) {
	name := c.PostForm("name")
	email := c.PostForm("email")
	password := c.PostForm("password")
	confirmPassword := c.PostForm("confirmpassword")
	user:=usecase.SignupInput{
		Name: name,
		Email: email,
		Password: password,
		ConfirmPassword: confirmPassword,
	}
	if err := h.usecase.AddAdmin(user); err != nil {
		adminValue,_:=c.Get("admin_value")
		admin:=adminValue.(*domain.User)
		users,errr:=h.usecase.GetAdminDashboardUsers(repository.UserListOptions{})
		if errr != nil{
			c.AbortWithStatus(500)
			return
		}
		c.HTML(400,"admin-dashboard.html",gin.H{
			"Name":             name,
			"Email":            email,
			"admin":            admin,
			"users":            users,
			"openAddUserModal": true,
			"adderror":         err,
		})
		return
	}
	c.Redirect(302, "/admin/dashboard")
}