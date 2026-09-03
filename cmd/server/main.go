package main

import (
	"log"
	"usermanagement/internal/config"
	"usermanagement/internal/delivery/http/handler"
	"usermanagement/internal/delivery/http/routes"
	"usermanagement/internal/infrastructure/database"
	"usermanagement/internal/repository/postgres"
	"usermanagement/internal/usecase"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal("Failed to load configuration:", err)
	}
	db, err := database.ConnectDB(*cfg)
	if err != nil {
		log.Fatal("Database Connection Failed")
	}

	userRepo := postgres.NewUserRepository(db)
	userUsecase := usecase.NewUserusecase(userRepo)
	userHandler := handler.NewUserhandler(userUsecase)

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

	routes.SetupRoutes(r, userHandler, userRepo)
	if err := r.Run(":8080"); err != nil {
		return
	}
}
