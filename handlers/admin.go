package handlers

import (
	"errors"
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
		Logger.Debug("already logined admin logged succefully", "admin_id", adminId)
		c.Redirect(302, "/superadmin/dashboard")
	}
	c.HTML(200, "admin-login.html", nil)
}

// superadmin
func SuperadmindminLogout(c *gin.Context) {
	session := sessions.DefaultMany(c, "admin_session")
	adminId := session.Get("admin_id")
	session.Clear()
	ses := session.Save()
	if ses != nil {
		Logger.Error("Logout Error: session save failed", "error", ses)
		c.HTML(200, "superadmin-dashboard.html", gin.H{
			"error": "Unable to Logout",
		})
		return
	}
	Logger.Info("Admin Logged out succefully", "admin_id", adminId)
	c.Redirect(302, "/admin/login")
}
func Adminlogin(c *gin.Context) {
	email := c.PostForm("email")
	password := c.PostForm("password")
	if email == "" || password == "" {
		Logger.Warn("AdminLogin Error: empty fields", "email", email)
		c.HTML(200, "admin-login.html", gin.H{
			"Email": email,
			"error": "Fields can't be empty",
		})
		return
	}
	var user models.User
	result := database.DB.Where("email = ?", email).First(&user)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		Logger.Warn("AdminLogin Error: invalid credentials", "email", email)
		c.HTML(200, "admin-login.html", gin.H{
			"Email": email,
			"error": "Invalid Credentils",
		})
		return
	} else if result.Error != nil {
		Logger.Error("AdminLogin Error: database query failed", "email", email, "error", result.Error)
		c.HTML(200, "admin-login.html", gin.H{
			"Email": email,
			"error": "Something Went Wrong",
		})
		return
	} else {
		res := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
		if res != nil {
			Logger.Warn("Adminlogin Error: Invalid Credentials", "email", email)
			c.HTML(200, "admin-login.html", gin.H{
				"Email": email,
				"error": "Invalid Credentials",
			})
			return
		} else {
			if user.IsBlocked {
				Logger.Warn("Adminlogin Error: Account has been blocked", "email", email)
				c.HTML(200, "admin-login.html", gin.H{
					"Email": email,
					"error": "Your account has been Blocked",
				})
				return
			} else {
				if user.Role == "user" {
					Logger.Warn("AdminLogin Error: User not authorized", "email", email)
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
						Logger.Error("AdminLogin Error: session save failed", "email", email, "error", err)
						c.HTML(200, "admin-login.html", gin.H{
							"Email": email,
							"error": "Something Went Wrong",
						})
						return
					}
					switch user.Role {
					case "admin":
						Logger.Info("Admin Logined Succefully", "email", email)
						c.Redirect(302, "/admin/dashboard")
					case "superadmin":
						Logger.Info("Super Admin Logined Succefully", "email", email)
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
		Logger.Warn(
			"Unauthorized access to super admin dashboard",
			"path", c.Request.URL.Path,
		)
		c.Redirect(302, "/admin/login")
		return
	}
	admin := models.User{}
	res := database.DB.First(&admin, adminID)
	if res.Error != nil {
		Logger.Error("SuperAdminDashboard Error: database query failed", "admin_id", adminID, "error", res.Error)
		c.HTML(200, "admin-login.html", gin.H{
			"error": "Something Went Wrong",
		})
		return
	}
	if admin.IsBlocked {
		Logger.Warn("SuperAdminDashboard Error: Account has been blocked", "admin_id", adminID)
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
			Logger.Error("SuperAdminDashboard Error: database query failed", "admin_id", adminID, "error", res.Error)
			c.HTML(200, "superadmin-dashboard.html", gin.H{
				"admin": admin,
				"error": "Unable to Fetch users",
			})
			return
		}
		Logger.Debug("SuperAdmin feched users succefully", "admin_id", adminID)
		c.HTML(200, "superadmin-dashboard.html", gin.H{
			"admin": admin,
			"users": users,
		})
		return
	} else {
		Logger.Warn("SuperAdminDashboard error: unauthorized access", "admin_id", adminID)
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
		Logger.Warn(
			"Unauthorized access to super admin dashboard",
			"path", c.Request.URL.Path,
		)
		c.Redirect(302, "admin/login")
		return
	}
	var checkAdmin models.User
	res := database.DB.Where("id = ?", admin_id).First(&checkAdmin)
	if res.Error != nil {
		Logger.Error("Super Admin editUser error: database query failed", "admin_id", admin_id, "error", res.Error)
		c.HTML(403, "admin-login.html", gin.H{
			"error": "Something Went Wrong",
		})
		return
	}
	if checkAdmin.IsBlocked {
		Logger.Warn("Super Admin editUser error: admin account has been blocked", "admin_id", admin_id, "error", res.Error)
		c.HTML(403, "admin-login.html", gin.H{
			"error": "You are not authorized",
		})
		return
	}
	if checkAdmin.Role != "superadmin" {
		Logger.Warn("Super Admin editUser error: Unauthorised admin Access", "admin_id", admin_id, "error", res.Error)
		c.HTML(403, "admin-login.html", gin.H{
			"error": "You are not authorized",
		})
		return
	}
	var users []models.User
	query := database.DB
	res = query.Find(&users)
	if res.Error != nil {
		Logger.Error("Super Admin editUser error: database query failed: user feching", "admin_id", admin_id, "error", res.Error)
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
		Logger.Error("Super Admin editUser error: database query failed", "admin_id", admin_id, "user_id", id, "error", resu.Error)
		c.HTML(403, "superadmin-dashboard.html", gin.H{
			"admin": checkAdmin,
			"error": "Something Went Wrong",
		})
		return
	}
	if user.ID == 1 && user.Role == "superadmin" {
		Logger.Warn("Super Admin editUser error: trying to edit primary admin", "admin_id", admin_id, "user_id", id, "error", resu.Error)
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
		Logger.Error("Super Admin editUser error: database query failed", "admin_id", admin_id, "user_id", id, "error", resuu.Error)

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
		Logger.Error("Super Admin editUser error: user Updation failed", "admin_id", admin_id, "user_id", id, "error", result)
		c.HTML(403, "superadmin-dashboard.html", gin.H{
			"admin": checkAdmin,
			"users": users,
			"error": "Unable to update User",
		})
		return
	}
	Logger.Info("SuperAdmin EditUser: User updated succefully", "admin_id", admin_id, "user_id", id)
	c.Redirect(302, "/superadmin/dashboard")
}
func Deleteuser(c *gin.Context) {

	session := sessions.DefaultMany(c, "admin_session")

	adminID := session.Get("admin_id")

	if adminID == nil {

		Logger.Warn(
			"Unauthorized attempt to delete user",
			"path", c.Request.URL.Path,
		)

		c.Redirect(http.StatusFound, "/admin/login")
		return
	}
	var checkAdmin models.User

	res := database.DB.Where("id = ?", adminID).First(&checkAdmin)

	if res.Error != nil {

		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			Logger.Warn(
				"Delete user failed: admin not found",
				"admin_id", adminID,
			)
		} else {
			Logger.Error(
				"Delete user failed: database query for admin failed",
				"admin_id", adminID,
				"error", res.Error,
			)
		}

		c.HTML(http.StatusForbidden, "admin-login.html", gin.H{
			"error": "Something Went Wrong",
		})
		return
	}
	if checkAdmin.IsBlocked {

		Logger.Warn(
			"Blocked admin attempted to delete a user",
			"admin_id", adminID,
		)

		c.HTML(http.StatusForbidden, "admin-login.html", gin.H{
			"error": "Your account has been blocked",
		})
		return
	}

	if checkAdmin.Role != "superadmin" {

		Logger.Warn(
			"Unauthorized admin attempted to delete a user",
			"admin_id", adminID,
			"role", checkAdmin.Role,
		)

		c.HTML(http.StatusForbidden, "admin-login.html", gin.H{
			"error": "You are not authorized",
		})
		return
	}
	var users []models.User

	res = database.DB.Find(&users)

	if res.Error != nil {

		Logger.Error(
			"Delete user failed: unable to fetch users",
			"admin_id", adminID,
			"error", res.Error,
		)

		c.HTML(http.StatusInternalServerError, "superadmin-dashboard.html", gin.H{
			"admin": checkAdmin,
			"error": "Unable to Fetch users",
		})
		return
	}

	targetUserID := c.Param("id")

	var user models.User

	res = database.DB.First(&user, targetUserID)

	if res.Error != nil {

		if errors.Is(res.Error, gorm.ErrRecordNotFound) {

			Logger.Warn(
				"Delete user failed: target user not found",
				"admin_id", adminID,
				"target_user_id", targetUserID,
			)

		} else {

			Logger.Error(
				"Delete user failed: database query for target user failed",
				"admin_id", adminID,
				"target_user_id", targetUserID,
				"error", res.Error,
			)
		}

		c.HTML(http.StatusForbidden, "superadmin-dashboard.html", gin.H{
			"admin": checkAdmin,
			"users": users,
			"error": "Something Went Wrong",
		})
		return
	}
	if user.ID == 1 && user.Role == "superadmin" {

		Logger.Warn(
			"Attempt to delete primary superadmin",
			"admin_id", adminID,
			"target_user_id", user.ID,
		)

		c.HTML(http.StatusForbidden, "superadmin-dashboard.html", gin.H{
			"admin": checkAdmin,
			"users": users,
			"error": "Primary Superadmin cannot be deleted",
		})
		return
	}
	result := database.DB.Unscoped().Delete(&models.User{}, targetUserID)

	if result.Error != nil {

		Logger.Error(
			"Delete user failed: database delete operation failed",
			"admin_id", adminID,
			"target_user_id", user.ID,
			"error", result.Error,
		)

		c.HTML(http.StatusInternalServerError, "superadmin-dashboard.html", gin.H{
			"admin": checkAdmin,
			"users": users,
			"error": "Unable to Delete",
		})
		return
	}
	Logger.Info(
		"User deleted successfully",
		"admin_id", adminID,
		"target_user_id", user.ID,
	)

	c.Redirect(http.StatusFound, "/superadmin/dashboard")
}
func BlockUserSuperAdmin(c *gin.Context) {
	session := sessions.DefaultMany(c, "admin_session")

	adminID := session.Get("admin_id")

	if adminID == nil {
		Logger.Warn(
			"Unauthorized attempt to block or unblock user",
			"path", c.Request.URL.Path,
		)

		c.Redirect(http.StatusFound, "/admin/login")
		return
	}

	var checkAdmin models.User

	res := database.DB.Where("id = ?", adminID).First(&checkAdmin)

	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			Logger.Warn(
				"Block user failed: admin not found",
				"admin_id", adminID,
			)
		} else {
			Logger.Error(
				"Block user failed: database query for admin failed",
				"admin_id", adminID,
				"error", res.Error,
			)
		}

		c.HTML(http.StatusForbidden, "admin-login.html", gin.H{
			"error": "Something Went Wrong",
		})
		return
	}

	if checkAdmin.IsBlocked {
		Logger.Warn(
			"Blocked admin attempted to block or unblock a user",
			"admin_id", adminID,
		)

		c.HTML(http.StatusForbidden, "admin-login.html", gin.H{
			"error": "Your account has been Blocked",
		})
		return
	}

	if checkAdmin.Role != "superadmin" {
		Logger.Warn(
			"Unauthorized admin attempted to block or unblock a user",
			"admin_id", adminID,
			"role", checkAdmin.Role,
		)

		c.HTML(http.StatusForbidden, "admin-login.html", gin.H{
			"error": "You are not authorized",
		})
		return
	}

	var users []models.User

	res = database.DB.Find(&users)

	if res.Error != nil {
		Logger.Error(
			"Block user failed: unable to fetch users",
			"admin_id", adminID,
			"error", res.Error,
		)

		c.HTML(http.StatusInternalServerError, "superadmin-dashboard.html", gin.H{
			"admin": checkAdmin,
			"error": "Unable to Fetch users",
		})
		return
	}

	targetUserID := c.Param("id")

	var user models.User

	res = database.DB.First(&user, targetUserID)

	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			Logger.Warn(
				"Block user failed: target user not found",
				"admin_id", adminID,
				"target_user_id", targetUserID,
			)
		} else {
			Logger.Error(
				"Block user failed: database query for target user failed",
				"admin_id", adminID,
				"target_user_id", targetUserID,
				"error", res.Error,
			)
		}

		c.HTML(http.StatusForbidden, "superadmin-dashboard.html", gin.H{
			"admin": checkAdmin,
			"users": users,
			"error": "Something Went Wrong",
		})
		return
	}

	if user.ID == 1 && user.Role == "superadmin" {
		Logger.Warn(
			"Attempt to block or unblock primary superadmin",
			"admin_id", adminID,
			"target_user_id", user.ID,
		)

		c.HTML(http.StatusForbidden, "superadmin-dashboard.html", gin.H{
			"admin": checkAdmin,
			"users": users,
			"error": "Primary Superadmin cannot be edited",
		})
		return
	}

	newBlockedStatus := !user.IsBlocked

	result := database.DB.Model(&user).
		Where("id = ?", targetUserID).
		Update("is_blocked", newBlockedStatus)

	if result.Error != nil {
		Logger.Error(
			"Block user failed: database update failed",
			"admin_id", adminID,
			"target_user_id", user.ID,
			"error", result.Error,
		)

		c.HTML(http.StatusInternalServerError, "superadmin-dashboard.html", gin.H{
			"admin": checkAdmin,
			"users": users,
			"error": "Unable to Block",
		})
		return
	}

	if newBlockedStatus {
		Logger.Info(
			"User blocked successfully",
			"admin_id", adminID,
			"target_user_id", user.ID,
		)
	} else {
		Logger.Info(
			"User unblocked successfully",
			"admin_id", adminID,
			"target_user_id", user.ID,
		)
	}

	c.Redirect(http.StatusFound, "/superadmin/dashboard")

}
func AdduserSuperAdmin(c *gin.Context) {
	session := sessions.DefaultMany(c, "admin_session")

	adminID := session.Get("admin_id")

	if adminID == nil {
		Logger.Warn(
			"Unauthorized attempt to add user",
			"path", c.Request.URL.Path,
		)

		c.Redirect(http.StatusFound, "/admin/login")
		return
	}

	var checkAdmin models.User

	res := database.DB.Where("id = ?", adminID).First(&checkAdmin)

	if res.Error != nil {

		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			Logger.Warn(
				"Add user failed: admin not found",
				"admin_id", adminID,
			)
		} else {
			Logger.Error(
				"Add user failed: database query for admin failed",
				"admin_id", adminID,
				"error", res.Error,
			)
		}

		c.HTML(http.StatusForbidden, "admin-login.html", gin.H{
			"error": "Something Went Wrong",
		})
		return
	}

	if checkAdmin.IsBlocked {
		Logger.Warn(
			"Blocked admin attempted to add user",
			"admin_id", adminID,
		)

		c.HTML(http.StatusForbidden, "admin-login.html", gin.H{
			"error": "You are not authorized",
		})
		return
	}

	if checkAdmin.Role != "admin" && checkAdmin.Role != "superadmin" {
		Logger.Warn(
			"Unauthorized role attempted to add user",
			"admin_id", adminID,
			"role", checkAdmin.Role,
		)

		c.HTML(http.StatusForbidden, "admin-login.html", gin.H{
			"error": "You are not authorized",
		})
		return
	}

	var users []models.User

	res = database.DB.Find(&users)

	if res.Error != nil {
		Logger.Error(
			"Add user failed: unable to fetch users",
			"admin_id", adminID,
			"error", res.Error,
		)

		c.HTML(http.StatusInternalServerError, "superadmin-dashboard.html", gin.H{
			"admin": checkAdmin,
			"error": "Something Went Wrong",
		})
		return
	}

	name := c.PostForm("name")
	email := c.PostForm("email")
	role := c.PostForm("role")
	password := c.PostForm("password")
	confirmPassword := c.PostForm("confirmpassword")

	if name == "" || email == "" || password == "" || confirmPassword == "" || role == "" {
		Logger.Warn(
			"Add user validation failed: empty fields",
			"admin_id", adminID,
		)

		c.HTML(http.StatusBadRequest, "superadmin-dashboard.html", gin.H{
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
		Logger.Warn(
			"Add user validation failed: weak password",
			"admin_id", adminID,
		)

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

	if password != confirmPassword {
		Logger.Warn(
			"Add user validation failed: password mismatch",
			"admin_id", adminID,
		)

		c.HTML(http.StatusBadRequest, "superadmin-dashboard.html", gin.H{
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
		Logger.Warn(
			"Add user validation failed: invalid email format",
			"admin_id", adminID,
		)

		c.HTML(http.StatusBadRequest, "superadmin-dashboard.html", gin.H{
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
		Logger.Warn(
			"Add user validation failed: invalid name",
			"admin_id", adminID,
		)

		c.HTML(http.StatusBadRequest, "superadmin-dashboard.html", gin.H{
			"admin":            checkAdmin,
			"users":            users,
			"Name":             name,
			"Email":            email,
			"adderror":         "Name can only contain letters and spaces",
			"openAddUserModal": true,
		})
		return
	}

	var existingUser models.User

	res = database.DB.Where("email = ?", email).First(&existingUser)

	if errors.Is(res.Error, gorm.ErrRecordNotFound) {

		hashPassword, err := bcrypt.GenerateFromPassword(
			[]byte(password),
			bcrypt.DefaultCost,
		)

		if err != nil {
			Logger.Error(
				"Add user failed: password hashing failed",
				"admin_id", adminID,
				"error", err,
			)

			c.HTML(http.StatusInternalServerError, "superadmin-dashboard.html", gin.H{
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
			Password: string(hashPassword),
		}

		result := database.DB.Create(&newUser)

		if result.Error != nil {
			Logger.Error(
				"Add user failed: database create operation failed",
				"admin_id", adminID,
				"role", role,
				"error", result.Error,
			)

			c.HTML(http.StatusInternalServerError, "superadmin-dashboard.html", gin.H{
				"admin":            checkAdmin,
				"users":            users,
				"Name":             name,
				"Email":            email,
				"adderror":         "Unable to create User",
				"openAddUserModal": true,
			})
			return
		}

		Logger.Info(
			"User added successfully",
			"admin_id", adminID,
			"new_user_id", newUser.ID,
			"role", newUser.Role,
		)

		c.Redirect(http.StatusFound, "/superadmin/dashboard")
		return
	}

	if res.Error != nil {
		Logger.Error(
			"Add user failed: database query for existing user failed",
			"admin_id", adminID,
			"error", res.Error,
		)

		c.HTML(http.StatusInternalServerError, "superadmin-dashboard.html", gin.H{
			"admin":            checkAdmin,
			"users":            users,
			"Name":             name,
			"Email":            email,
			"adderror":         "Something Went Wrong",
			"openAddUserModal": true,
		})
		return
	}

	Logger.Warn(
		"Add user failed: email already exists",
		"admin_id", adminID,
	)

	c.HTML(http.StatusBadRequest, "superadmin-dashboard.html", gin.H{
		"admin":            checkAdmin,
		"users":            users,
		"adderror":         "User already existing",
		"Name":             name,
		"Email":            email,
		"openAddUserModal": true,
	})

}

// admin
func AdminLogout(c *gin.Context) {
	session := sessions.DefaultMany(c, "admin_session")
	adminID := session.Get("admin_id")
	session.Clear()
	err := session.Save()
	if err != nil {
		Logger.Error(
			"Admin logout failed: session save failed",
			"admin_id", adminID,
			"error", err,
		)
		c.HTML(http.StatusInternalServerError, "admin-dashboard.html", gin.H{
			"error": "Unable to Logout",
		})
		return
	}
	Logger.Info(
		"Admin logged out successfully",
		"admin_id", adminID,
	)
	c.Redirect(http.StatusFound, "/admin/login")
}
func AdminDashboard(c *gin.Context) {
	session := sessions.DefaultMany(c, "admin_session")
	adminID := session.Get("admin_id")
	if adminID == nil {
		Logger.Warn(
			"Unauthorized access to admin dashboard",
			"path", c.Request.URL.Path,
		)
		c.Redirect(http.StatusFound, "/admin/login")
		return
	}
	var admin models.User
	res := database.DB.First(&admin, adminID)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			Logger.Warn(
				"Admin dashboard access failed: admin not found",
				"admin_id", adminID,
			)
		} else {
			Logger.Error(
				"Admin dashboard failed: database query for admin failed",
				"admin_id", adminID,
				"error", res.Error,
			)
		}
		c.HTML(http.StatusInternalServerError, "admin-login.html", gin.H{
			"error": "Something Went Wrong",
		})
		return
	}
	if admin.IsBlocked {
		Logger.Warn(
			"Blocked admin attempted to access admin dashboard",
			"admin_id", adminID,
		)
		c.HTML(http.StatusForbidden, "admin-login.html", gin.H{
			"error": "Your account has been blocked",
		})
		return
	}
	if admin.Role != "admin" && admin.Role != "superadmin" {
		Logger.Warn(
			"Unauthorized role attempted to access admin dashboard",
			"admin_id", adminID,
			"role", admin.Role,
		)
		c.HTML(http.StatusForbidden, "admin-login.html", gin.H{
			"error": "You are not authorized person",
		})
		return
	}
	var users []models.User
	search := c.Query("search")
	sort := c.Query("sort")
	query := database.DB.Where(
		"role NOT IN ?",
		[]string{"admin", "superadmin"},
	)
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
		query = query.Where(
			"name ILIKE ? OR email ILIKE ?",
			"%"+search+"%",
			"%"+search+"%",
		).Order("id ASC")
	}
	res = query.Find(&users)
	if res.Error != nil {
		Logger.Error(
			"Admin dashboard failed: unable to fetch users",
			"admin_id", adminID,
			"error", res.Error,
		)
		c.HTML(http.StatusInternalServerError, "admin-login.html", gin.H{
			"error": "Something Went Wrong",
		})
		return
	}
	Logger.Debug(
		"Users fetched for admin dashboard",
		"admin_id", adminID,
		"user_count", len(users),
	)
	c.HTML(http.StatusOK, "admin-dashboard.html", gin.H{
		"admin": admin,
		"users": users,
	})
	return
}
func Edituseradmin(c *gin.Context) {
	session := sessions.DefaultMany(c, "admin_session")
	adminID := session.Get("admin_id")
	if adminID == nil {
		Logger.Warn(
			"Unauthorized attempt to edit user",
			"path", c.Request.URL.Path,
		)
		c.Redirect(http.StatusFound, "/admin/login")
		return
	}
	var checkAdmin models.User
	res := database.DB.Where("id = ?", adminID).First(&checkAdmin)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			Logger.Warn(
				"Edit user failed: admin not found",
				"admin_id", adminID,
			)
		} else {
			Logger.Error(
				"Edit user failed: database query for admin failed",
				"admin_id", adminID,
				"error", res.Error,
			)
		}
		c.HTML(http.StatusForbidden, "admin-login.html", gin.H{
			"error": "Something Went Wrong",
		})
		return
	}
	if checkAdmin.IsBlocked {
		Logger.Warn(
			"Blocked admin attempted to edit user",
			"admin_id", adminID,
		)
		c.HTML(http.StatusForbidden, "admin-login.html", gin.H{
			"error": "You are not authorized",
		})
		return
	}
	if checkAdmin.Role != "admin" && checkAdmin.Role != "superadmin" {
		Logger.Warn(
			"Unauthorized role attempted to edit user",
			"admin_id", adminID,
			"role", checkAdmin.Role,
		)
		c.HTML(http.StatusForbidden, "admin-login.html", gin.H{
			"error": "You are not authorized",
		})
		return
	}
	var users []models.User
	query := database.DB.Where(
		"role NOT IN ?",
		[]string{"admin", "superadmin"},
	)
	res = query.Find(&users)
	if res.Error != nil {
		Logger.Error(
			"Edit user failed: unable to fetch users",
			"admin_id", adminID,
			"error", res.Error,
		)
		c.HTML(http.StatusInternalServerError, "admin-login.html", gin.H{
			"error": "Something Went Wrong",
		})
		return
	}
	targetUserID := c.Param("id")
	name := c.PostForm("name")
	email := c.PostForm("email")
	var existingUser models.User
	res = database.DB.
		Where("email = ? AND id != ?", email, targetUserID).
		First(&existingUser)
	if res.Error == nil {
		Logger.Warn(
			"Edit user failed: email already exists",
			"admin_id", adminID,
			"target_user_id", targetUserID,
		)
		c.HTML(http.StatusBadRequest, "admin-dashboard.html", gin.H{
			"admin": checkAdmin,
			"users": users,
			"error": "Email already exists",
			"Name":  name,
			"Email": email,
		})
		return
	}
	if !errors.Is(res.Error, gorm.ErrRecordNotFound) {
		Logger.Error(
			"Edit user failed: database query for existing email failed",
			"admin_id", adminID,
			"target_user_id", targetUserID,
			"error", res.Error,
		)
		c.HTML(http.StatusInternalServerError, "admin-dashboard.html", gin.H{
			"admin": checkAdmin,
			"users": users,
			"error": "Something Went Wrong",
			"Name":  name,
			"Email": email,
		})
		return
	}
	result := database.DB.
		Where("id = ?", targetUserID).
		Updates(&models.User{
			Name:  name,
			Email: email,
		})
	if result.Error != nil {
		Logger.Error(
			"Edit user failed: database update failed",
			"admin_id", adminID,
			"target_user_id", targetUserID,
			"error", result.Error,
		)
		c.HTML(http.StatusInternalServerError, "admin-dashboard.html", gin.H{
			"admin": checkAdmin,
			"users": users,
			"error": "Unable to update",
			"Name":  name,
			"Email": email,
		})
		return
	}
	Logger.Info(
		"User updated successfully",
		"admin_id", adminID,
		"target_user_id", targetUserID,
	)
	c.Redirect(http.StatusFound, "/admin/dashboard")
}
func Deleteuseradmin(c *gin.Context) {
	session := sessions.DefaultMany(c, "admin_session")
	adminID := session.Get("admin_id")
	if adminID == nil {
		Logger.Warn(
			"Unauthorized attempt to delete user",
			"path", c.Request.URL.Path,
		)
		c.Redirect(http.StatusFound, "/admin/login")
		return
	}
	var checkAdmin models.User
	res := database.DB.Where("id = ?", adminID).First(&checkAdmin)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			Logger.Warn(
				"Delete user failed: admin not found",
				"admin_id", adminID,
			)
		} else {
			Logger.Error(
				"Delete user failed: database query for admin failed",
				"admin_id", adminID,
				"error", res.Error,
			)
		}
		c.HTML(http.StatusForbidden, "admin-login.html", gin.H{
			"error": "Something Went Wrong",
		})
		return
	}
	if checkAdmin.IsBlocked {
		Logger.Warn(
			"Blocked admin attempted to delete user",
			"admin_id", adminID,
		)
		c.HTML(http.StatusForbidden, "admin-login.html", gin.H{
			"error": "You are not authorized",
		})
		return
	}
	if checkAdmin.Role != "admin" && checkAdmin.Role != "superadmin" {
		Logger.Warn(
			"Unauthorized role attempted to delete user",
			"admin_id", adminID,
			"role", checkAdmin.Role,
		)
		c.HTML(http.StatusForbidden, "admin-login.html", gin.H{
			"error": "You are not authorized",
		})
		return
	}
	var users []models.User
	query := database.DB.Where(
		"role NOT IN ?",
		[]string{"admin", "superadmin"},
	)
	res = query.Find(&users)
	if res.Error != nil {
		Logger.Error(
			"Delete user failed: unable to fetch users",
			"admin_id", adminID,
			"error", res.Error,
		)
		c.HTML(http.StatusInternalServerError, "admin-login.html", gin.H{
			"error": "Something Went Wrong",
		})
		return
	}
	targetUserID := c.Param("id")
	var user models.User
	res = database.DB.First(&user, targetUserID)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			Logger.Warn(
				"Delete user failed: target user not found",
				"admin_id", adminID,
				"target_user_id", targetUserID,
			)
		} else {
			Logger.Error(
				"Delete user failed: database query for target user failed",
				"admin_id", adminID,
				"target_user_id", targetUserID,
				"error", res.Error,
			)
		}
		c.HTML(http.StatusForbidden, "admin-dashboard.html", gin.H{
			"admin": checkAdmin,
			"users": users,
			"error": "Something Went Wrong",
		})
		return
	}
	if user.ID == 1 && user.Role == "superadmin" {
		Logger.Warn(
			"Attempt to delete primary superadmin",
			"admin_id", adminID,
			"target_user_id", user.ID,
		)
		c.HTML(http.StatusForbidden, "admin-dashboard.html", gin.H{
			"admin": checkAdmin,
			"users": users,
			"error": "Primary Superadmin cannot be edited",
		})
		return
	}
	result := database.DB.Unscoped().Delete(&models.User{}, targetUserID)
	if result.Error != nil {
		Logger.Error(
			"Delete user failed: database delete operation failed",
			"admin_id", adminID,
			"target_user_id", user.ID,
			"error", result.Error,
		)
		c.HTML(http.StatusInternalServerError, "admin-dashboard.html", gin.H{
			"admin": checkAdmin,
			"users": users,
			"error": "Unable to delete User",
		})
		return
	}
	Logger.Info(
		"User deleted successfully",
		"admin_id", adminID,
		"target_user_id", user.ID,
	)
	c.Redirect(http.StatusFound, "/admin/dashboard")
}
func BlockUserAdmin(c *gin.Context) {
	session := sessions.DefaultMany(c, "admin_session")
	adminID := session.Get("admin_id")
	if adminID == nil {
		Logger.Warn(
			"Unauthorized attempt to block or unblock user",
			"path", c.Request.URL.Path,
		)
		c.Redirect(http.StatusFound, "/admin/login")
		return
	}
	var checkAdmin models.User
	res := database.DB.Where("id = ?", adminID).First(&checkAdmin)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			Logger.Warn(
				"Block user failed: admin not found",
				"admin_id", adminID,
			)
		} else {
			Logger.Error(
				"Block user failed: database query for admin failed",
				"admin_id", adminID,
				"error", res.Error,
			)
		}
		c.HTML(http.StatusForbidden, "admin-login.html", gin.H{
			"error": "Something Went Wrong",
		})
		return
	}
	if checkAdmin.IsBlocked {
		Logger.Warn(
			"Blocked admin attempted to block or unblock user",
			"admin_id", adminID,
		)
		c.HTML(http.StatusForbidden, "admin-login.html", gin.H{
			"error": "You are not authorized",
		})
		return
	}
	if checkAdmin.Role != "admin" && checkAdmin.Role != "superadmin" {
		Logger.Warn(
			"Unauthorized role attempted to block or unblock user",
			"admin_id", adminID,
			"role", checkAdmin.Role,
		)
		c.HTML(http.StatusForbidden, "admin-login.html", gin.H{
			"error": "You are not authorized",
		})
		return
	}
	var users []models.User
	query := database.DB.Where(
		"role NOT IN ?",
		[]string{"admin", "superadmin"},
	)
	res = query.Find(&users)
	if res.Error != nil {
		Logger.Error(
			"Block user failed: unable to fetch users",
			"admin_id", adminID,
			"error", res.Error,
		)
		c.HTML(http.StatusInternalServerError, "admin-login.html", gin.H{
			"error": "Something Went Wrong",
		})
		return
	}
	targetUserID := c.Param("id")
	var user models.User
	res = database.DB.First(&user, targetUserID)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			Logger.Warn(
				"Block user failed: target user not found",
				"admin_id", adminID,
				"target_user_id", targetUserID,
			)
		} else {
			Logger.Error(
				"Block user failed: database query for target user failed",
				"admin_id", adminID,
				"target_user_id", targetUserID,
				"error", res.Error,
			)
		}
		c.HTML(http.StatusForbidden, "admin-dashboard.html", gin.H{
			"admin": checkAdmin,
			"users": users,
			"error": "Something Went Wrong",
		})
		return
	}
	if user.ID == 1 && user.Role == "superadmin" {
		Logger.Warn(
			"Attempt to block or unblock primary superadmin",
			"admin_id", adminID,
			"target_user_id", user.ID,
		)
		c.HTML(http.StatusForbidden, "admin-dashboard.html", gin.H{
			"admin": checkAdmin,
			"users": users,
			"error": "Primary Superadmin cannot be edited",
		})
		return
	}
	newBlockedStatus := !user.IsBlocked
	result := database.DB.
		Model(&user).
		Where("id = ?", targetUserID).
		Update("is_blocked", newBlockedStatus)
	if result.Error != nil {
		Logger.Error(
			"Block user failed: database update failed",
			"admin_id", adminID,
			"target_user_id", user.ID,
			"error", result.Error,
		)
		c.HTML(http.StatusInternalServerError, "admin-dashboard.html", gin.H{
			"admin": checkAdmin,
			"users": users,
			"error": "Unable to Block",
		})
		return
	}
	if newBlockedStatus {
		Logger.Info(
			"User blocked successfully",
			"admin_id", adminID,
			"target_user_id", user.ID,
		)
	} else {
		Logger.Info(
			"User unblocked successfully",
			"admin_id", adminID,
			"target_user_id", user.ID,
		)
	}
	c.Redirect(http.StatusFound, "/admin/dashboard")
}
func AdduserAdmin(c *gin.Context) {
	session := sessions.DefaultMany(c, "admin_session")
	adminID := session.Get("admin_id")
	if adminID == nil {
		Logger.Warn(
			"Unauthorized attempt to add user",
			"path", c.Request.URL.Path,
		)
		c.Redirect(http.StatusFound, "/admin/login")
		return
	}
	var checkAdmin models.User
	res := database.DB.Where("id = ?", adminID).First(&checkAdmin)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			Logger.Warn(
				"Add user failed: admin not found",
				"admin_id", adminID,
			)
		} else {
			Logger.Error(
				"Add user failed: database query for admin failed",
				"admin_id", adminID,
				"error", res.Error,
			)
		}
		c.HTML(http.StatusForbidden, "admin-login.html", gin.H{
			"error": "Something Went Wrong",
		})
		return
	}
	if checkAdmin.IsBlocked {
		Logger.Warn(
			"Blocked admin attempted to add user",
			"admin_id", adminID,
		)
		c.HTML(http.StatusForbidden, "admin-login.html", gin.H{
			"error": "You are not authorized",
		})
		return
	}
	if checkAdmin.Role != "admin" && checkAdmin.Role != "superadmin" {
		Logger.Warn(
			"Unauthorized role attempted to add user",
			"admin_id", adminID,
			"role", checkAdmin.Role,
		)
		c.HTML(http.StatusForbidden, "admin-login.html", gin.H{
			"error": "You are not authorized",
		})
		return
	}
	var users []models.User
	res = database.DB.
		Where("role NOT IN ?", []string{"admin", "superadmin"}).
		Find(&users)
	if res.Error != nil {
		Logger.Error(
			"Add user failed: unable to fetch users",
			"admin_id", adminID,
			"error", res.Error,
		)
		c.HTML(http.StatusInternalServerError, "admin-dashboard.html", gin.H{
			"admin": checkAdmin,
			"error": "Something Went Wrong",
		})
		return
	}
	name := c.PostForm("name")
	email := c.PostForm("email")
	password := c.PostForm("password")
	confirmPassword := c.PostForm("confirmpassword")
	if name == "" || email == "" || password == "" || confirmPassword == "" {
		Logger.Warn(
			"Add user validation failed: empty fields",
			"admin_id", adminID,
		)
		c.HTML(http.StatusBadRequest, "admin-dashboard.html", gin.H{
			"Name":             name,
			"Email":            email,
			"admin":            checkAdmin,
			"users":            users,
			"adderror":         "Fields can't be empty",
			"openAddUserModal": true,
		})
		return
	}
	if !isStrongPassword(password) {
		Logger.Warn(
			"Add user validation failed: weak password",
			"admin_id", adminID,
		)
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
	if password != confirmPassword {
		Logger.Warn(
			"Add user validation failed: password mismatch",
			"admin_id", adminID,
		)

		c.HTML(http.StatusBadRequest, "admin-dashboard.html", gin.H{
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
		Logger.Warn(
			"Add user validation failed: invalid email format",
			"admin_id", adminID,
		)
		c.HTML(http.StatusBadRequest, "admin-dashboard.html", gin.H{
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
		Logger.Warn(
			"Add user validation failed: invalid name",
			"admin_id", adminID,
		)
		c.HTML(http.StatusBadRequest, "admin-dashboard.html", gin.H{
			"Name":             name,
			"Email":            email,
			"admin":            checkAdmin,
			"users":            users,
			"openAddUserModal": true,
			"adderror":         "Name can only contain letters and spaces",
		})
		return
	}
	var existingUser models.User
	res = database.DB.Where("email = ?", email).First(&existingUser)
	if res.Error == nil {
		Logger.Warn(
			"Add user failed: email already exists",
			"admin_id", adminID,
		)
		c.HTML(http.StatusBadRequest, "admin-dashboard.html", gin.H{
			"Name":             name,
			"Email":            email,
			"admin":            checkAdmin,
			"users":            users,
			"adderror":         "User Already Existing",
			"openAddUserModal": true,
		})
		return
	}
	if !errors.Is(res.Error, gorm.ErrRecordNotFound) {
		Logger.Error(
			"Add user failed: database query for existing user failed",
			"admin_id", adminID,
			"error", res.Error,
		)
		c.HTML(http.StatusInternalServerError, "admin-dashboard.html", gin.H{
			"Name":             name,
			"Email":            email,
			"admin":            checkAdmin,
			"users":            users,
			"adderror":         "Something Went Wrong",
			"openAddUserModal": true,
		})
		return
	}
	hashPassword, err := bcrypt.GenerateFromPassword(
		[]byte(password),
		bcrypt.DefaultCost,
	)
	if err != nil {
		Logger.Error(
			"Add user failed: password hashing failed",
			"admin_id", adminID,
			"error", err,
		)
		c.HTML(http.StatusInternalServerError, "admin-dashboard.html", gin.H{
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
		Password: string(hashPassword),
	}
	result := database.DB.Create(&newUser)
	if result.Error != nil {
		Logger.Error(
			"Add user failed: database create operation failed",
			"admin_id", adminID,
			"error", result.Error,
		)
		c.HTML(http.StatusInternalServerError, "admin-dashboard.html", gin.H{
			"Name":             name,
			"Email":            email,
			"admin":            checkAdmin,
			"users":            users,
			"adderror":         "Unable to create User",
			"openAddUserModal": true,
		})
		return
	}
	Logger.Info(
		"User added successfully",
		"admin_id", adminID,
		"new_user_id", newUser.ID,
	)
	c.Redirect(http.StatusFound, "/admin/dashboard")
}
