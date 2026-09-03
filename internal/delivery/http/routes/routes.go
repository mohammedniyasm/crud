package routes

import (
	"log/slog"
	"usermanagement/internal/delivery/http/handler"
	"usermanagement/internal/delivery/http/middleware"
	"usermanagement/internal/repository"

	"github.com/gin-gonic/gin"
)

func SetupRoutes(
	router *gin.Engine,
	userHandler *handler.Userhandler,
	repo repository.UserRepository,
	Logger *slog.Logger,
) {

	// User guest routes
	userGuest := router.Group("/")
	userGuest.Use(middleware.RedirectIfUserAuth(Logger))

	userGuest.GET("/signup", userHandler.SignupPage)
	userGuest.POST("/signup", userHandler.Signup)

	userGuest.GET("/login", userHandler.LoginPage)
	userGuest.POST("/login", userHandler.Login)

	// User protected routes

	protectedUser := router.Group("/")
	protectedUser.Use(middleware.RequireUserAuth(Logger))

	protectedUser.GET("/home", userHandler.Home)
	protectedUser.GET("/logout", userHandler.Logout)

	// Admin guest routes
	adminGuest := router.Group("/admin")
	adminGuest.Use(middleware.RedirectIfAdminAuth(repo,Logger))

	adminGuest.GET("/login", userHandler.AdminLoginPage)
	adminGuest.POST("/login", userHandler.AdminLogin)

	// Admin protected routes
	admin := router.Group("/admin")
	admin.Use(middleware.RequireAdminAuth(repo,Logger))

	admin.GET("/dashboard", userHandler.AdminDashboard)
	admin.POST("/block/:id", userHandler.AdminBlock)
	admin.POST("/edit/:id", userHandler.AdminEdit)
	admin.POST("/delete/:id", userHandler.AdminDelete)
	admin.POST("/add", userHandler.AdminAddUser)
	admin.GET("/logout", userHandler.AdminLogout)

	// SuperAdmin protected routes

	superadmin := router.Group("/superadmin")
	superadmin.Use(middleware.RequireAdminAuth(repo,Logger), middleware.RequireSuperAdminAuth(Logger))

	superadmin.GET("/dashboard", userHandler.SuperAdminDashboard)
	superadmin.POST("/block/:id", userHandler.SuperAdminBlock)
	superadmin.POST("/edit/:id", userHandler.SuperAdminEdit)
	superadmin.POST("/delete/:id", userHandler.SuperAdminDelete)
	superadmin.POST("/add", userHandler.SuperAdminAddUser)
	superadmin.GET("/logout", userHandler.AdminLogout)

}
