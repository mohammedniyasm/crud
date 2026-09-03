package middleware

import (
	"log/slog"
	"usermanagement/internal/domain"
	"usermanagement/internal/repository"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

func RequireUserAuth(Logger *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.DefaultMany(c, "user_session")
		userID := session.Get("user_id")

		if userID == nil {
			Logger.Debug("user authentication failed: no session")
			c.Redirect(303, "/login")
			c.Abort()
			return
		}
		c.Set("user_id", userID)
		c.Next()
	}
}
func RedirectIfUserAuth(Logger *slog.Logger) gin.HandlerFunc {
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
func RequireAdminAuth(repo repository.UserRepository, Logger *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.DefaultMany(c, "admin_session")

		adminIDValue := session.Get("admin_id")
		if adminIDValue == nil {
			Logger.Debug("admin authentication failed: no session")
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
			Logger.Warn("admin authentication failed: invalid session user ID")
			c.Redirect(302, "/admin/login")
			c.Abort()
			return
		}

		admin, err := repo.FindById(adminID)
		if err != nil {
			session.Clear()
			_ = session.Save()
			Logger.Warn("admin authentication failed: user not found", "user_id", adminID)
			c.Redirect(302, "/admin/login")
			c.Abort()
			return
		}

		if admin.IsBlocked {
			Logger.Warn("admin access denied: account blocked", "user_id", adminID)
			session.Set("auth_error", "Your account has been blocked")

			if err := session.Save(); err != nil {
				Logger.Error("Failed to save blocked-account session", "user_id", adminID, "error", err.Error())
				c.AbortWithStatus(500)
				return
			}

			c.Redirect(302, "/admin/login")
			c.Abort()
			return
		}

		if admin.Role != "admin" && admin.Role != "superadmin" {
			Logger.Warn("admin access denied: account insuffiesient role", "user_id", adminID, "role", admin.Role)
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
func RedirectIfAdminAuth(repo repository.UserRepository, Logger *slog.Logger) gin.HandlerFunc {
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
			Logger.Warn("admin authentication failed: invalid session user ID")
			c.Next()
			return
		}
		admin, err := repo.FindById(adminID)
		if err != nil {
			session.Clear()
			_ = session.Save()
			Logger.Warn("admin authentication failed: user not found", "user_id",adminID)
			c.Next()
			return
		}
		if admin.IsBlocked {
			Logger.Warn("admin authentication failed: account blocked","user_id",adminID)
			c.Next()
			return
		}
		if admin.Role != "admin" && admin.Role != "superadmin" {
			Logger.Warn("admin access denied: user not have previliaged access","user_id",adminID,"user_role",admin.Role)
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
func RequireSuperAdminAuth(Logger *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		adminValue, exists := c.Get("admin_value")
		if !exists {
			Logger.Error("superadmin authorization failed: admin context missing",)
			c.AbortWithStatus(402)
			return
		}
		admin, ok := adminValue.(*domain.User)
		if !ok {
			Logger.Error("superadmin authorization failed: invalid admin context",)
			c.AbortWithStatus(500)
			return
		}
		if admin.Role != "superadmin" {
			Logger.Warn("superadmin access denied: insufficient privileges","user_id", admin.ID,"user_role", admin.Role,)
			c.Redirect(302, "/admin/dashboard")
			c.Abort()
			return
		}
		c.Next()
	}
}
