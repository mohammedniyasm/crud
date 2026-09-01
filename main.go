package main

import (
	"usermanagement/database"
	"usermanagement/handlers"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

func main() {
	database.ConnectDB()
	r := gin.Default()
	userStore := cookie.NewStore([]byte("user_secret_key"))
	adminStore := cookie.NewStore([]byte("admin_secret_key"))
	userStore.Options(sessions.Options{
		Path: "/",
		MaxAge: 86400,
		HttpOnly: true,
		Secure: false,
	})
	adminStore.Options(sessions.Options{
		Path: "/",
		MaxAge: 86400,
		HttpOnly: true,
		Secure: false,
	})
	r.Use(sessions.SessionsManyStores([]sessions.SessionStore{
		{
			Name:  "user_session",
			Store: userStore,
		},
		{
			Name:  "admin_session",
			Store: adminStore,
		},
	}))

	r.LoadHTMLGlob("./templates/*")
	r.Static("/static", "./static")

	r.GET("/signup", handlers.Signuppage)
	r.GET("/login", handlers.Loginpage)
	r.GET("/home", handlers.Home)
	r.GET("/logout", handlers.Logout)
	r.POST("/login", handlers.Login)
	r.POST("/signup", handlers.Signup)

	r.GET("/admin/login", handlers.AdminloginPage)
	r.POST("/admin/login", handlers.Adminlogin)

	r.GET("/admin/logout", handlers.AdminLogout)
	r.GET("/superadmin/logout", handlers.SuperadmindminLogout)

	r.GET("/superadmin/dashboard", handlers.SuperAdminDashboard)
	r.GET("/admin/dashboard", handlers.AdminDashboard)

	r.POST("/superadmin/edit/:id", handlers.Edituser)
	r.POST("/admin/edit/:id", handlers.Edituseradmin)

	r.POST("/admin/delete/:id", handlers.Deleteuseradmin)
	r.POST("/superadmin/delete/:id", handlers.Deleteuser)

	r.POST("/admin/add", handlers.AdduserAdmin)
	r.POST("/superadmin/add", handlers.AdduserSuperAdmin)

	r.POST("/superadmin/block/:id", handlers.BlockUserSuperAdmin)
	r.POST("/admin/block/:id", handlers.BlockUserAdmin)

	r.Run(":8080")
}
