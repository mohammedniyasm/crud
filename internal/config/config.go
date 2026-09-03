package config

import (
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	DBHost             string
	DBUser             string
	DBPassword         string
	DBName             string
	DBPort             string
	UserSessionSecret  string
	AdminSessionSecret string
}

func Load() (*Config, error) {

	if err := godotenv.Load(); err != nil {
		return nil, err
	}

	return &Config{
		DBHost:             os.Getenv("DB_HOST"),
		DBUser:             os.Getenv("DB_USER"),
		DBPassword:         os.Getenv("DB_PASSWORD"),
		DBName:             os.Getenv("DB_NAME"),
		DBPort:             os.Getenv("DB_PORT"),
		UserSessionSecret:  os.Getenv("USER_SESSION_SECRET"),
		AdminSessionSecret: os.Getenv("ADMIN_SESSION_SECRET"),
	}, nil
}
