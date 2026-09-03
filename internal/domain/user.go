package domain

import (
	"time"
)

type User struct {
	ID uint
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time
	Name string 
	Email string 
	Password string 
	Role string 
	IsBlocked bool 
	IsPrimarySA bool 
}