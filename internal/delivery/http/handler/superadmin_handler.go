package handler

import (
	"strconv"
	"usermanagement/internal/domain"
	"usermanagement/internal/repository"
	"usermanagement/internal/usecase"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

func (h *Userhandler) SuperAdminLogout(c *gin.Context) {
	session := sessions.DefaultMany(c, "admin_session")
	userid:=session.Get("admin_id")
	session.Clear()
	if err := session.Save(); err != nil {
		h.logger.Error("superadmin logout failed: session saving failed","user_id",userid,"error",err.Error())
		c.HTML(500, "superadmin-dashboard.html", gin.H{
			"error": "Unable to logout",
		})
		return
	}
	c.Redirect(302, "/admin/login")
}
func (h *Userhandler) SuperAdminDashboard(c *gin.Context) {
	session := sessions.DefaultMany(c, "admin_session")
	errormessage := session.Get("error")
	session.Delete("error")
	_ = session.Save()
	AdminValue, _ := c.Get("admin_value")
	admin := AdminValue.(*domain.User)
	sort := c.Query("sort")
	search := c.Query("search")
	users, err := h.usecase.GetSuperadminDashboardUsers(repository.UserListOptions{
		Search: search,
		Sort:   sort,
	})
	if err != nil {
		c.HTML(500, "superadmin-dashboard.html", gin.H{
			"error": "something went wrong",
		})
		return
	}
	c.HTML(200, "superadmin-dashboard.html", gin.H{
		"admin": admin,
		"users": users,
		"error": errormessage,
	})
}
func (h *Userhandler) SuperAdminBlock(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.Redirect(302, "/superadmin/dashboard")
		return
	}
	targetUserid := uint(id)
	if err := h.usecase.BlockAdmin(targetUserid); err != nil {
		session := sessions.DefaultMany(c, "admin_session")
		session.Set("error", err)
		if errr := session.Save(); errr != nil {
			h.logger.Error("superadmin block operation failed: session saving failed","user_id",targetUserid,"error",err.Error())
			c.AbortWithStatus(500)
			return
		}
		c.Redirect(302, "/superadmin/dashboard")
		return
	}
	c.Redirect(302, "/superadmin/dashboard")
}
func (h *Userhandler) SuperAdminEdit(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.Redirect(302, "/admin/dashboard")
		return
	}
	targetUserid := uint(id)
	name := c.PostForm("name")
	email := c.PostForm("email")
	role := c.PostForm("role")
	if err := h.usecase.EditSuperAdmin(targetUserid, name, email, role); err != nil {
		session := sessions.DefaultMany(c, "admin_session")
		session.Set("error", err.Error())
		if errr := session.Save(); errr != nil {
			h.logger.Error("superadmin edit operation failed: session saving failed","user_id",targetUserid,"error",err.Error())
			c.AbortWithStatus(500)
			return
		}
		c.Redirect(302, "/superadmin/dashboard")
		return
	}
	c.Redirect(302, "/superadmin/dashboard")
}
func (h *Userhandler) SuperAdminDelete(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.Redirect(302, "/superadmin/dashboard")
		return
	}
	targetUserid := uint(id)
	if err := h.usecase.DeleteAdmin(targetUserid); err != nil {
		session := sessions.DefaultMany(c, "admin_session")
		session.Set("error", err)
		if errr := session.Save(); errr != nil {
			h.logger.Error("superadmin delete operation failed: session saving failed","user_id",targetUserid,"error",err.Error())
			c.AbortWithStatus(500)
			return
		}
		c.Redirect(302, "/superadmin/dashboard")
		return
	}
	c.Redirect(302, "/superadmin/dashboard")
}
func (h *Userhandler) SuperAdminAddUser(c *gin.Context) {
	name := c.PostForm("name")
	email := c.PostForm("email")
	role := c.PostForm("role")
	password := c.PostForm("password")
	confirmPassword := c.PostForm("confirmpassword")
	user := usecase.SuperAdminAdduser{
		Name:            name,
		Email:           email,
		Role:            role,
		Password:        password,
		ConfirmPassword: confirmPassword,
	}
	if err := h.usecase.AddSuperAdmin(user); err != nil {
		adminValue, _ := c.Get("admin_value")
		admin := adminValue.(*domain.User)
		users, errr := h.usecase.GetSuperadminDashboardUsers(repository.UserListOptions{})
		if errr != nil {
			c.AbortWithStatus(500)
			return
		}
		c.HTML(400, "superadmin-dashboard.html", gin.H{
			"Name":             name,
			"Email":            email,
			"admin":            admin,
			"users":            users,
			"openAddUserModal": true,
			"adderror":         err,
		})
		return
	}
	c.Redirect(302, "/superadmin/dashboard")
}
