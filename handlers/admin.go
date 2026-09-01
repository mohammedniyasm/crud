package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"regexp"
	"usermanagement/database"
	"usermanagement/models"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func AdminloginPage(c *gin.Context) {
	session := sessions.DefaultMany(c, "admin_session")
	adminId := session.Get("admin_id")
	if adminId != nil {
		c.Redirect(302, "/superadmin/dashboard")
	}
	c.HTML(200, "admin-login.html", nil)
}

// superadmin
func SuperadmindminLogout(c *gin.Context) {
	session := sessions.DefaultMany(c, "admin_session")
	session.Clear()
	ses := session.Save()
	if ses != nil {
		c.HTML(200, "superadmin-dashboard.html", gin.H{
			"error": "Unable to Logout",
		})
	}
	c.Redirect(302, "/admin/login")
}
func Adminlogin(c *gin.Context) {
	email := c.PostForm("email")
	password := c.PostForm("password")
	if email == "" || password == "" {
		c.HTML(200, "admin-login.html", gin.H{
			"Email": email,
			"error": "Fields can't be empty",
		})
		return
	}
	var user models.User
	result := database.DB.Where("email = ?", email).First(&user)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		c.HTML(200, "admin-login.html", gin.H{
			"Email": email,
			"error": "Invalid Credentils",
		})
		return
	} else if result.Error != nil {
		c.HTML(200, "admin-login.html", gin.H{
			"Email": email,
			"error": "Something Went Wrong",
		})
		return
	} else {
		res := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
		if res != nil {
			c.HTML(200, "admin-login.html", gin.H{
				"Email": email,
				"error": "Invalid Credentials",
			})
			return
		} else {
			if user.IsBlocked {
				c.HTML(200, "admin-login.html", gin.H{
					"Email": email,
					"error": "Your account has been Blocked",
				})
				return
			} else {
				if user.Role == "user" {
					c.HTML(200, "admin-login.html", gin.H{
						"Email": email,
						"error": "You are not authorized person",
					})
					return
				} else {
					session := sessions.DefaultMany(c, "admin_session")
					session.Set("admin_id", user.ID)
					session.Set("admin_name", user.Name)
					err := session.Save()
					if err != nil {
						c.HTML(200, "admin-login.html", gin.H{
							"Email": email,
							"error": "Something Went Wrong",
						})
						return
					}
					switch user.Role {
					case "admin":
						c.Redirect(302, "/admin/dashboard")
					case "superadmin":
						c.Redirect(302, "/superadmin/dashboard")
					default:
						c.HTML(200, "admin-login.html", gin.H{
							"Email": email,
							"error": "You are not authorized person",
						})
					}
				}
			}
		}
	}
}
func SuperAdminDashboard(c *gin.Context) {
	session := sessions.DefaultMany(c, "admin_session")
	adminID := session.Get("admin_id")
	if adminID == nil {
		c.Redirect(302, "/admin/login")
		return
	}
	admin := models.User{}
	res := database.DB.First(&admin, adminID)
	if res.Error != nil {
		c.HTML(200, "admin-login.html", gin.H{
			"error": "Something Went Wrong",
		})
		return
	}
	if admin.IsBlocked {
		c.HTML(200, "admin-login.html", gin.H{
			"error": "Your account has been blocked",
		})
		return
	}
	if admin.Role == "superadmin" {
		var users []models.User
		search := c.Query("search")
		sort := c.Query("sort")
		query := database.DB
		switch sort {
		case "az":
			query = query.Order("name ASC")
		case "za":
			query = query.Order("name DESC")
		case "new":
			query = query.Order("id DESC")
		case "old":
			query = query.Order("id ASC")
		}
		if search != "" {
			query = query.Where("name ILIKE ? OR email ILIKE ?", "%"+search+"%", "%"+search+"%")
		}
		res = query.Find(&users)
		if res.Error != nil {
			c.HTML(200, "superadmin-dashboard.html", gin.H{
				"admin": admin,
				"error": "Unable to Fetch users",
			})
			return
		}
		c.HTML(200, "superadmin-dashboard.html", gin.H{
			"admin": admin,
			"users": users,
		})
		return
	} else {
		c.HTML(200, "admin-login.html", gin.H{
			"error": "You are not authorized person",
		})
		return
	}
}
func Edituser(c *gin.Context) {
	session := sessions.DefaultMany(c, "admin_session")
	admin_id := session.Get("admin_id")
	if admin_id == nil {
		c.Redirect(302, "admin/login")
		return
	}
	var checkAdmin models.User
	res := database.DB.Where("id = ?", admin_id).First(&checkAdmin)
	if res.Error != nil {
		c.HTML(403, "admin-login.html", gin.H{
			"error": "Something Went Wrong",
		})
		return
	}
	if checkAdmin.IsBlocked {
		c.HTML(403, "admin-login.html", gin.H{
			"error": "You are not authorized",
		})
		return
	}
	if checkAdmin.Role != "superadmin" {
		c.HTML(403, "admin-login.html", gin.H{
			"error": "You are not authorized",
		})
	}
	var users []models.User
	query := database.DB
	res = query.Find(&users)
	if res.Error != nil {
		c.HTML(200, "superadmin-dashboard.html", gin.H{
			"admin": checkAdmin,
			"error": "Unable to Fetch users",
		})
		return
	}
	id := c.Param("id")
	name := c.PostForm("name")
	email := c.PostForm("email")
	role := c.PostForm("role")
	var user models.User
	resu := database.DB.First(&user, id)
	if resu.Error != nil {
		c.HTML(403, "superadmin-dashboard.html", gin.H{
			"admin": checkAdmin,
			"error": "Something Went Wrong",
		})
		return
	}
	if user.ID == 1 && user.Role == "superadmin" {
		c.HTML(403, "superadmin-dashboard.html", gin.H{
			"admin": checkAdmin,
			"users": users,
			"error": "Primary Superadmin cannot be edited",
		})
		return
	}
	var existingUser models.User

	resuu := database.DB.
		Where("email = ? AND id != ?", email, id).
		First(&existingUser)

	if resuu.Error == nil {
		c.HTML(403, "superadmin-dashboard.html", gin.H{
			"admin": checkAdmin,
			"users": users,
			"error": "Email already exists",
		})
		return
	}
	result := database.DB.Where("id = ?", id).Updates(&models.User{
		Name:  name,
		Email: email,
		Role:  role,
	}).Error
	if result != nil {
		c.HTML(403, "superadmin-dashboard.html", gin.H{
			"admin": checkAdmin,
			"users": users,
			"error": "Unable to update User",
		})
		return
	}
	c.Redirect(302, "/superadmin/dashboard")
}
func Deleteuser(c *gin.Context) {
	session := sessions.DefaultMany(c, "admin_session")
	admin_id := session.Get("admin_id")
	if admin_id == nil {
		c.Redirect(302, "admin/login")
		return
	}
	var checkAdmin models.User
	res := database.DB.Where("id = ?", admin_id).First(&checkAdmin)
	if res.Error != nil {
		c.HTML(403, "admin-login.html", gin.H{
			"error": "Something Went Wrong",
		})
		return
	}
	if checkAdmin.IsBlocked {
		c.HTML(403, "admin-login.html", gin.H{
			"error": "Your account has been blocked",
		})
		return
	}
	if checkAdmin.Role != "superadmin" {
		c.HTML(403, "admin-login.html", gin.H{
			"error": "You are not authorized",
		})
	}
	var users []models.User
	query := database.DB
	res = query.Find(&users)
	if res.Error != nil {
		c.HTML(200, "superadmin-dashboard.html", gin.H{
			"admin": checkAdmin,
			"error": "Unable to Fetch users",
		})
		return
	}
	id := c.Param("id")
	var user models.User
	resu := database.DB.First(&user, id)
	if resu.Error != nil {
		c.HTML(403, "superadmin-dashboard.html", gin.H{
			"admin": checkAdmin,
			"users": users,
			"error": "Something Went Wrong",
		})
		return
	}
	if user.ID == 1 && user.Role == "superadmin" {
		c.HTML(403, "superadmin-dashboard.html", gin.H{
			"admin": checkAdmin,
			"users": users,
			"error": "Primary Superadmin cannot be Delete",
		})
		return
	}
	result := database.DB.Unscoped().Delete(&models.User{}, id)
	if result.Error != nil {
		c.HTML(200, "superadmin-dashboard.html", gin.H{
			"admin": checkAdmin,
			"users": users,
			"error": "Unable to Delete",
		})
		return
	}
	c.Redirect(302, "/superadmin/dashboard")
}
func BlockUserSuperAdmin(c *gin.Context) {
	session := sessions.DefaultMany(c, "admin_session")
	admin_id := session.Get("admin_id")
	if admin_id == nil {
		c.Redirect(302, "admin/login")
		return
	}
	var checkAdmin models.User
	res := database.DB.Where("id = ?", admin_id).First(&checkAdmin)
	if res.Error != nil {
		c.HTML(403, "admin-login.html", gin.H{
			"error": "Something Went Wrong",
		})
		return
	}
	if checkAdmin.IsBlocked {
		c.HTML(403, "admin-login.html", gin.H{
			"error": "Your account has been Blocked",
		})
		return
	}
	if checkAdmin.Role != "superadmin" {
		c.HTML(403, "admin-login.html", gin.H{
			"error": "You are not authorized",
		})
	}
	var users []models.User
	query := database.DB
	res = query.Find(&users)
	if res.Error != nil {
		c.HTML(200, "superadmin-dashboard.html", gin.H{
			"admin": checkAdmin,
			"error": "Unable to Fetch users",
		})
		return
	}
	id := c.Param("id")
	var user models.User
	resu := database.DB.First(&user, id)
	if resu.Error != nil {
		c.HTML(403, "superadmin-dashboard.html", gin.H{
			"admin": checkAdmin,
			"users": users,
			"error": "Something Went Wrong",
		})
		return
	}
	if user.ID == 1 && user.Role == "superadmin" {
		c.HTML(403, "superadmin-dashboard.html", gin.H{
			"admin": checkAdmin,
			"users": users,
			"error": "Primary Superadmin cannot be edited",
		})
		return
	}
	result := database.DB.Model(&user).Where("id = ?", id).Update("is_blocked", !user.IsBlocked)
	if result.Error != nil {
		c.HTML(200, "superadmin-dashboard.html", gin.H{
			"admin": checkAdmin,
			"users": users,
			"error": "Unable to Block",
		})
		return
	}
	c.Redirect(302, "/superadmin/dashboard")
}
func AdduserSuperAdmin(c *gin.Context) {
	session := sessions.DefaultMany(c, "admin_session")
	admin_id := session.Get("admin_id")
	if admin_id == nil {
		c.Redirect(302, "/admin/login")
		return
	}
	var checkAdmin models.User
	res := database.DB.Where("id = ?", admin_id).First(&checkAdmin)
	if res.Error != nil {
		c.HTML(403, "admin-login.html", gin.H{
			"error": "Something Went Wrong",
		})
		return
	}
	if checkAdmin.IsBlocked {
		c.HTML(403, "admin-login.html", gin.H{
			"error": "You are not authorized",
		})
		return
	}
	if checkAdmin.Role != "admin" && checkAdmin.Role != "superadmin" {
		c.HTML(403, "admin-login.html", gin.H{
			"error": "You are not authorized",
		})
		return
	}
	var users []models.User
	res = database.DB.Find(&users)
	if res.Error != nil {
		c.HTML(403, "admin-dashboard.html", gin.H{
			"error": "Something Went Wrong",
		})
		return
	}
	name := c.PostForm("name")
	email := c.PostForm("email")
	role := c.PostForm("role")
	password := c.PostForm("password")
	confirmpassword := c.PostForm("confirmpassword")
	
	if name == "" || email == "" || password == "" || confirmpassword == "" || role == "" {
		c.HTML(200, "superadmin-dashboard.html", gin.H{
			"admin":            checkAdmin,
			"users":            users,
			"Name":             name,
			"Email":            email,
			"adderror":         "Fields can't be empty",
			"openAddUserModal": true,
		})
		return
	}
	if !isStrongPassword(password) {
		c.HTML(http.StatusBadRequest, "superadmin-dashboard.html", gin.H{
			"admin":            checkAdmin,
			"users":            users,
			"Name":             name,
			"Email":            email,
			"adderror":         "Password must contain at least 8 characters, one uppercase letter, one lowercase letter, one number, and one special character",
			"openAddUserModal": true,
		})
		return
	}
	if password != confirmpassword {
		c.HTML(200, "superadmin-dashboard.html", gin.H{
			"admin":            checkAdmin,
			"users":            users,
			"Name":             name,
			"Email":            email,
			"adderror":         "Passwords must be match",
			"openAddUserModal": true,
		})
		return
	}

	_, err := mail.ParseAddress(email)
	if err != nil {
		c.HTML(200, "superadmin-dashboard.html", gin.H{
			"admin":            checkAdmin,
			"users":            users,
			"Name":             name,
			"Email":            email,
			"adderror":         "Enter a valid email",
			"openAddUserModal": true,
		})
		return
	}
	namePattern := regexp.MustCompile(`^[a-zA-Z ]+$`)
	if !namePattern.MatchString(name) {
		c.HTML(200, "superadmin-dashboard.html", gin.H{
			"admin":            checkAdmin,
			"users":            users,
			"Name":             name,
			"Email":            email,
			"adderror":         "Name can only contain letters and spaces",
			"openAddUserModal": true,
		})
		return
	}
	var existinguser models.User
	res = database.DB.Where("email = ?", email).First(&existinguser)
	if errors.Is(res.Error, gorm.ErrRecordNotFound) {
		hashpassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			c.HTML(200, "superadmin-dashboard.html", gin.H{
				"admin":            checkAdmin,
				"users":            users,
				"Name":             name,
				"Email":            email,
				"adderror":         "Something Went Wrong",
				"openAddUserModal": true,
			})
			return
		}
		newUser := models.User{
			Name:     name,
			Email:    email,
			Role:     role,
			Password: string(hashpassword),
		}
		result := database.DB.Create(&newUser)
		if result.Error != nil {
			c.HTML(200, "superadmin-dashboard.html", gin.H{
				"admin":            checkAdmin,
				"users":            users,
				"Name":             name,
				"Email":            email,
				"adderror":         "Unable to create User",
				"openAddUserModal": true,
			})
			return
		}
		c.Redirect(302, "/superadmin/dashboard")
	} else {
		c.HTML(200, "superadmin-dashboard.html", gin.H{
			"admin":            checkAdmin,
			"users":            users,
			"adderror":         "User already existing",
			"Name":             name,
			"Email":            email,
			"openAddUserModal": true,
		})
	}
}

// admin
func AdminLogout(c *gin.Context) {
	session := sessions.DefaultMany(c, "admin_session")
	session.Clear()
	ses := session.Save()
	if ses != nil {
		c.HTML(200, "admin-dashboard.html", gin.H{
			"error": "Unable to Logout",
		})
	}
	c.Redirect(302, "/admin/login")
}
func AdminDashboard(c *gin.Context) {
	session := sessions.DefaultMany(c, "admin_session")
	adminID := session.Get("admin_id")
	if adminID == nil {
		c.Redirect(302, "/admin/login")
		return
	}
	admin := models.User{}
	res := database.DB.First(&admin, adminID)
	if res.Error != nil {
		c.HTML(200, "admin-login.html", gin.H{
			"error": "Something Went Wrong",
		})
		return
	}
	if admin.IsBlocked {
		c.HTML(200, "admin-login.html", gin.H{
			"error": "Your account has been blocked",
		})
		return
	}
	if admin.Role == "admin" || admin.Role == "superadmin" {
		var users []models.User
		search := c.Query("search")
		sort := c.Query("sort")
		query := database.DB.Where("role NOT IN ?", []string{"admin", "superadmin"})
		switch sort {
		case "az":
			query = query.Order("name ASC")
		case "za":
			query = query.Order("name DESC")
		case "new":
			query = query.Order("id DESC")
		case "old":
			query = query.Order("id ASC")
		}
		if search != "" {
			query = query.Where("name ILIKE ? OR email ILIKE ?", "%"+search+"%", "%"+search+"%").Order("id ASC")
		}
		res = query.Find(&users)
		if res.Error != nil {
			c.HTML(200, "admin-login.html", gin.H{
				"error": "Something Went Wrong",
			})
			return
		}
		c.HTML(200, "admin-dashboard.html", gin.H{
			"admin": admin,
			"users": users,
		})
		return
	} else {
		c.HTML(200, "admin-login.html", gin.H{
			"error": "You are not authorized person",
		})
		return
	}
}
func Edituseradmin(c *gin.Context) {
	session := sessions.DefaultMany(c, "admin_session")
	admin_id := session.Get("admin_id")
	if admin_id == nil {
		c.Redirect(302, "admin/login")
		return
	}
	var checkAdmin models.User
	res := database.DB.Where("id = ?", admin_id).First(&checkAdmin)
	if res.Error != nil {
		c.HTML(403, "admin-login.html", gin.H{
			"error": "Something Went Wrong",
		})
		return
	}
	if checkAdmin.IsBlocked {
		c.HTML(403, "admin-login.html", gin.H{
			"error": "You are not authorized",
		})
		return
	}
	if checkAdmin.Role != "admin" && checkAdmin.Role != "superadmin" {
		c.HTML(403, "admin-login.html", gin.H{
			"error": "You are not authorized",
		})
		return
	}
	var users []models.User
	query := database.DB.Where("role NOT IN ?", []string{"admin", "superadmin"})
	res = query.Find(&users)
	if res.Error != nil {
		c.HTML(200, "admin-login.html", gin.H{
			"error": "Something Went Wrong",
		})
		return
	}
	id := c.Param("id")
	name := c.PostForm("name")
	email := c.PostForm("email")
	var existingUser models.User

	resuu := database.DB.
		Where("email = ? AND id != ?", email, id).
		First(&existingUser)

	if resuu.Error == nil {
		c.HTML(403, "superadmin-dashboard.html", gin.H{
			"admin": checkAdmin,
			"users": users,
			"error": "Email already exists",
		})
		return
	}
	result := database.DB.Where("id = ?", id).Updates(&models.User{
		Name:  name,
		Email: email,
	})
	if result.Error != nil {
		c.HTML(200, "admin-dashboard.html", gin.H{
			"admin": checkAdmin,
			"users": users,
			"error": "Unable to update",
		})
		return
	}
	c.Redirect(302, "/admin/dashboard")
}
func Deleteuseradmin(c *gin.Context) {
	session := sessions.DefaultMany(c, "admin_session")
	admin_id := session.Get("admin_id")
	if admin_id == nil {
		c.Redirect(302, "admin/login")
		return
	}
	var checkAdmin models.User
	res := database.DB.Where("id = ?", admin_id).First(&checkAdmin)
	if res.Error != nil {
		c.HTML(403, "admin-login.html", gin.H{
			"error": "Something Went Wrong",
		})
		return
	}
	if checkAdmin.IsBlocked {
		c.HTML(403, "admin-login.html", gin.H{
			"error": "You are not authorized",
		})
		return
	}
	if checkAdmin.Role != "admin" && checkAdmin.Role != "superadmin" {
		c.HTML(403, "admin-login.html", gin.H{
			"error": "You are not authorized",
		})
		return
	}
	var users []models.User
	query := database.DB.Where("role NOT IN ?", []string{"admin", "superadmin"})
	res = query.Find(&users)
	if res.Error != nil {
		c.HTML(200, "admin-login.html", gin.H{
			"error": "Something Went Wrong",
		})
		return
	}
	id := c.Param("id")
	var user models.User
	resu := database.DB.First(&user, id)
	if resu.Error != nil {
		c.HTML(403, "admin-dashboard.html", gin.H{
			"admin": checkAdmin,
			"users": users,
			"error": "Something Went Wrong",
		})
		return
	}
	if user.ID == 1 && user.Role == "superadmin" {
		c.HTML(403, "admin-dashboard.html", gin.H{
			"admin": checkAdmin,
			"users": users,
			"error": "Primary Superadmin cannot be edited",
		})
		return
	}
	result := database.DB.Unscoped().Delete(&models.User{}, id)
	if result.Error != nil {
		c.HTML(403, "admin-dashboard.html", gin.H{
			"admin": checkAdmin,
			"users": users,
			"error": "unable to delete User",
		})
		return
	}
	c.Redirect(302, "/admin/dashboard")
}
func BlockUserAdmin(c *gin.Context) {
	session := sessions.DefaultMany(c, "admin_session")
	admin_id := session.Get("admin_id")
	if admin_id == nil {
		c.Redirect(302, "admin/login")
		return
	}
	var checkAdmin models.User
	res := database.DB.Where("id = ?", admin_id).First(&checkAdmin)
	if res.Error != nil {
		c.HTML(403, "admin-dashboard.html", gin.H{
			"error": "Something Went Wrong",
		})
		return
	}
	if checkAdmin.IsBlocked {
		c.HTML(403, "admin-login.html", gin.H{
			"error": "You are not authorized",
		})
		return
	}
	if checkAdmin.Role != "superadmin" && checkAdmin.Role != "admin" {
		fmt.Println("Authorization failed")
		c.HTML(403, "admin-login.html", gin.H{
			"error": "You are not authorized",
		})
		return
	}
	var users []models.User
	query := database.DB.Where("role NOT IN ?", []string{"admin", "superadmin"})
	res = query.Find(&users)
	if res.Error != nil {
		c.HTML(200, "admin-login.html", gin.H{
			"error": "Something Went Wrong",
		})
		return
	}
	id := c.Param("id")
	var user models.User
	resu := database.DB.First(&user, id)
	if resu.Error != nil {
		c.HTML(403, "admin-dashboard.html", gin.H{
			"admin": checkAdmin,
			"users": users,
			"error": "Something Went Wrong",
		})
		return
	}
	if user.ID == 1 && user.Role == "superadmin" {
		c.HTML(403, "admin-dashboard.html", gin.H{
			"admin": checkAdmin,
			"users": users,
			"error": "Primary Superadmin cannot be edited",
		})
		return
	}
	result := database.DB.Model(&user).Where("id = ?", id).Update("is_blocked", !user.IsBlocked)
	if result.Error != nil {
		c.HTML(200, "admin-dashboard.html", gin.H{
			"admin": checkAdmin,
			"users": users,
			"error": "Unable to Block",
		})
		return
	}

	c.Redirect(302, "/admin/dashboard")
}
func AdduserAdmin(c *gin.Context) {
	session := sessions.DefaultMany(c, "admin_session")
	admin_id := session.Get("admin_id")
	if admin_id == nil {
		c.Redirect(302, "/admin/login")
		return
	}
	var checkAdmin models.User
	res := database.DB.Where("id = ?", admin_id).First(&checkAdmin)
	if res.Error != nil {
		c.HTML(403, "admin-login.html", gin.H{
			"error": "Something Went Wrong",
		})
		return
	}
	if checkAdmin.IsBlocked {
		c.HTML(403, "admin-login.html", gin.H{
			"error": "You are not authorized",
		})
		return
	}
	if checkAdmin.Role != "admin" && checkAdmin.Role != "superadmin" {
		c.HTML(403, "admin-login.html", gin.H{
			"error": "You are not authorized",
		})
		return
	}
	var users []models.User
	res = database.DB.Where("role NOT IN ?", []string{"admin", "superadmin"}).Find(&users)
	if res.Error != nil {
		c.HTML(403, "admin-dashboard.html", gin.H{
			"error": "Something Went Wrong",
		})
		return
	}
	name := c.PostForm("name")
	email := c.PostForm("email")
	password := c.PostForm("password")
	confirmpassword := c.PostForm("confirmpassword")
	if !isStrongPassword(password) {
		c.HTML(http.StatusBadRequest, "admin-dashboard.html", gin.H{
			"admin":            checkAdmin,
			"users":            users,
			"Name":             name,
			"Email":            email,
			"adderror":         "Password must contain at least 8 characters, one uppercase letter, one lowercase letter, one number, and one special character",
			"openAddUserModal": true,
		})
		return
	}
	if name == "" || email == "" || password == "" || confirmpassword == "" {
		c.HTML(200, "admin-dashboard.html", gin.H{
			"Name":             name,
			"Email":            email,
			"admin":            checkAdmin,
			"users":            users,
			"adderror":         "Fields can't be empty",
			"openAddUserModal": true,
		})
		return
	}
	if password != confirmpassword {
		c.HTML(200, "admin-dashboard.html", gin.H{
			"Name":             name,
			"Email":            email,
			"admin":            checkAdmin,
			"users":            users,
			"adderror":         "Passwords must be match",
			"openAddUserModal": true,
		})
		return
	}
	_, err := mail.ParseAddress(email)
	if err != nil {
		c.HTML(200, "admin-dashboard.html", gin.H{
			"Name":             name,
			"Email":            email,
			"admin":            checkAdmin,
			"users":            users,
			"adderror":         "Enter a valid email",
			"openAddUserModal": true,
		})
		return
	}
	namePattern := regexp.MustCompile(`^[a-zA-Z ]+$`)
	if !namePattern.MatchString(name) {
		c.HTML(200, "admin-dashboard.html", gin.H{
			"Name":             name,
			"Email":            email,
			"admin":            checkAdmin,
			"users":            users,
			"openAddUserModal": true,
			"adderror":         "Name can only contain letters and spaces",
		})
		return
	}
	var existinguser models.User
	res = database.DB.Where("email = ?", email).First(&existinguser)
	if errors.Is(res.Error, gorm.ErrRecordNotFound) {
		hashpassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			c.HTML(200, "admin-dashboard.html", gin.H{
				"Name":             name,
				"Email":            email,
				"admin":            checkAdmin,
				"users":            users,
				"adderror":         "Something Went Wrong",
				"openAddUserModal": true,
			})
			return
		}
		newUser := models.User{
			Name:     name,
			Email:    email,
			Password: string(hashpassword),
		}
		result := database.DB.Create(&newUser)
		if result.Error != nil {
			c.HTML(200, "admin-dashboard.html", gin.H{
				"Name":     name,
			"Email":    email,
				"admin":            checkAdmin,
				"users":            users,
				"adderror":         "Unable to create User",
				"openAddUserModal": true,
			})
			return
		}
		c.Redirect(302, "/admin/dashboard")
	} else {
		c.HTML(200, "admin-dashboard.html", gin.H{
			"Name":     name,
			"Email":    email,
			"admin":            checkAdmin,
			"users":            users,
			"adderror":         "User Already Existing",
			"openAddUserModal": true,
		})
	}
}
