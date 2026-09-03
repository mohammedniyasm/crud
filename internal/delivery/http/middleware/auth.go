package middleware

import (
	"usermanagement/internal/domain"
	"usermanagement/internal/repository"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

func RequireUserAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.DefaultMany(c, "user_session")
		userID := session.Get("user_id")

		if userID == nil {
			c.Redirect(303, "/login")
			c.Abort()
			return
		}

		c.Set("user_id", userID)
		c.Next()
	}
}
func RedirectIfUserAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.DefaultMany(c, "user_session")
		userID := session.Get("user_id")

		if userID != nil {
			c.Redirect(303, "/home")
			c.Abort()
			return
		}
		c.Next()
	}
}
func RequireAdminAuth(repo repository.UserRepository) gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.DefaultMany(c, "admin_session")

		adminIDValue := session.Get("admin_id")
		if adminIDValue == nil {
			c.Redirect(302, "/admin/login")
			c.Abort()
			return
		}

		var adminID uint

		switch id := adminIDValue.(type) {
		case uint:
			adminID = id
		case uint64:
			adminID = uint(id)
		case int:
			adminID = uint(id)
		case int64:
			adminID = uint(id)
		default:
			session.Clear()
			_ = session.Save()

			c.Redirect(302, "/admin/login")
			c.Abort()
			return
		}

		admin, err := repo.FindById(adminID)
		if err != nil {
			session.Clear()
			_ = session.Save()

			c.Redirect(302, "/admin/login")
			c.Abort()
			return
		}

		if admin.IsBlocked {
			session.Set("auth_error", "Your account has been blocked")

			if err := session.Save(); err != nil {
				c.AbortWithStatus(500)
				return
			}

			c.Redirect(302, "/admin/login")
			c.Abort()
			return
		}

		if admin.Role != "admin" && admin.Role != "superadmin" {
			session.Set("auth_error", "You are not authorized")

			if err := session.Save(); err != nil {
				c.AbortWithStatus(500)
				return
			}

			c.Redirect(302, "/admin/login")
			c.Abort()
			return
		}

		c.Set("admin_id", admin.ID)
		c.Set("admin_value", admin)

		c.Next()
	}
}
func RedirectIfAdminAuth(repo repository.UserRepository) gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.DefaultMany(c, "admin_session")
		adminIDValue := session.Get("admin_id")
		if adminIDValue == nil {
			c.Next()
			return
		}
		var adminID uint
		switch id := adminIDValue.(type) {
		case uint:
			adminID = id
		case uint64:
			adminID = uint(id)
		case int:
			adminID = uint(id)
		case int64:
			adminID = uint(id)
		default:
			session.Clear()
			_ = session.Save()
			c.Next()
			return
		}
		admin, err := repo.FindById(adminID)
		if err != nil {
			session.Clear()
			_ = session.Save()
			c.Next()
			return
		}
		if admin.IsBlocked {
			c.Next()
			return
		}
		if admin.Role != "admin" && admin.Role != "superadmin" {
			session.Clear()
			_ = session.Save()
			c.Next()
			return
		}
		if admin.Role == "admin" {
			c.Redirect(302, "/admin/dashboard")
			c.Abort()
			return
		}
		if admin.Role == "superadmin" {
			c.Redirect(302, "/superadmin/dashboard")
			c.Abort()
			return
		}

		c.Next()
	}
}
func RequireSuperAdminAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		adminValue, exists := c.Get("admin_value")
		if !exists {
			c.AbortWithStatus(402)
			return
		}
		admin, ok := adminValue.(*domain.User)
		if !ok {
			c.AbortWithStatus(500)
			return
		}
		if admin.Role != "superadmin" {
			c.Redirect(302, "/admin/dashboard")
			c.Abort()
			return
		}
		c.Next()
	}
}
