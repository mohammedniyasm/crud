package main

import (
	"usermanagement/internal/config"
	"usermanagement/internal/delivery/http/handler"
	"usermanagement/internal/delivery/http/routes"
	"usermanagement/internal/infrastructure/database"
	"usermanagement/internal/infrastructure/logger"
	"usermanagement/internal/repository/postgres"
	"usermanagement/internal/usecase"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

func main() {
	Logger := logger.NewLogger()
	Logger.Info("Application Started")
	cfg, err := config.Load()
	if err != nil {
		Logger.Error("Failed to Load Configuration")
		return
	}
	Logger.Info("configuration loaded successfully")

	db, err := database.ConnectDB(*cfg)
	if err != nil {
		Logger.Error("Failed to Connect Database")
		return
	}
	Logger.Info("database connected successfully")

	userRepo := postgres.NewUserRepository(db, Logger)
	userUsecase := usecase.NewUserusecase(userRepo, Logger)
	userHandler := handler.NewUserhandler(userUsecase, Logger)

	r := gin.Default()
	userStore := cookie.NewStore([]byte(cfg.UserSessionSecret))
	adminStore := cookie.NewStore([]byte(cfg.AdminSessionSecret))
	userStore.Options(sessions.Options{
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: true,
		Secure:   false,
	})
	adminStore.Options(sessions.Options{
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: true,
		Secure:   false,
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

	routes.SetupRoutes(r, userHandler, userRepo,Logger)
	Logger.Info("server started", "address", "http://localhost:8080")
	if err := r.Run(":8080"); err != nil {
		Logger.Error("Server stopped Unexpectedly", "error", err)
		return
	}
}
