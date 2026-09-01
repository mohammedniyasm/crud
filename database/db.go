package database

import (
	"fmt"
	"log"
	"usermanagement/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

func ConnectDB() {
	dsn := "host=localhost user=postgres password=Niyas@12 dbname=usermanagment port=5432 sslmode=disable"
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Database connection Failed", err)
	}
	DB = db
	fmt.Println("Database Connected")
	err = DB.AutoMigrate(&models.User{})
	if err != nil {
		log.Fatal("Migration Failed", err)
	}
	fmt.Println("Migration Completed")
}
