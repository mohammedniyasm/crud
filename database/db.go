package database

import (
	"fmt"
	"usermanagement/logger"
	"usermanagement/models"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

func ConnectDB() {
	log := logger.NewLogger()
	dsn := "host=localhost user=postgres password=Niyas@12 dbname=usermanagment port=5432 sslmode=disable"
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Error("Database connection Failed","error",err,)
		return
	}
	DB = db
	log.Info("Database Connected Succesfully")
	err = DB.AutoMigrate(&models.User{})
	if err != nil {
		log.Error("Migration Failed", "error",err,)
		return
	}
	fmt.Println("Migration Completed Succesfully")
}
