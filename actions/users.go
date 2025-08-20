package actions

import (
	"login/models"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gobuffalo/buffalo"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// POST /users
func UsersCreate(c buffalo.Context) error {
	user := &models.User{}
	if err := c.Bind(user); err != nil {
		return err
	}

	// hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	user.Password = string(hashedPassword)

	if err := models.DB.Create(user); err != nil {
		return err
	}

	return c.Render(201, r.JSON(user))
}

// POST /login
func UsersLogin(c buffalo.Context) error {
	loginData := struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}{}

	if err := c.Bind(&loginData); err != nil {
		return err
	}

	user := &models.User{}
	err := models.DB.Where("email = ?", loginData.Email).First(user)
	if err != nil {
		return c.Error(401, err)
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginData.Password))
	if err != nil {
		return c.Error(401, err)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": strconv.Itoa(user.ID),
		"email":   user.Email,
		"exp":     time.Now().Add(time.Hour * 72).Unix(),
	})

	secret := os.Getenv("JWT_SECRET")
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		return err
	}

	return c.Render(200, r.JSON(map[string]string{"token": tokenString}))

}

// getUser /api/users/{id}
var jwtSecret = []byte("your_secret_key") // Use same secret as login
func getUserById(c buffalo.Context) error {
	// ✅ Check Authorization Header
	authHeader := c.Request().Header.Get("Authorization")
	if authHeader == "" {
		return c.Render(http.StatusUnauthorized, r.JSON(map[string]string{
			"error": "Missing Authorization Header",
		}))
	}

	// ✅ Extract token from "Bearer <token>"
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == authHeader {
		return c.Render(http.StatusUnauthorized, r.JSON(map[string]string{
			"error": "Invalid Authorization Header format",
		}))
	}

	// ✅ Validate token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		return c.Render(http.StatusUnauthorized, r.JSON(map[string]string{
			"error": "Invalid or expired token",
		}))
	}

	// ✅ Get user ID from URL params
	userID := c.Param("id")

	// ✅ Fetch user from DB
	var user models.User
	err = models.DB.Find(&user, userID)
	if err != nil {
		return c.Render(http.StatusNotFound, r.JSON(map[string]string{
			"error": "User not found",
		}))
	}

	// ✅ Hide password
	user.Password = ""

	return c.Render(http.StatusOK, r.JSON(user))
}

// UpdateUser updates a user profile
func UpdateUser(c buffalo.Context) error {
	// Get user ID from URL
	userID := c.Param("id")

	// Find the existing user
	var user models.User
	err := models.DB.Find(&user, userID)
	if err != nil {
		return c.Render(http.StatusNotFound, r.JSON(map[string]string{
			"error": "User not found",
		}))
	}

	// Bind the incoming JSON body to user struct
	if err := c.Bind(&user); err != nil {
		return c.Render(http.StatusBadRequest, r.JSON(map[string]string{
			"error": "Invalid request body",
		}))
	}

	// Save the updated user data
	err = models.DB.Update(&user)
	if err != nil {
		return c.Render(http.StatusInternalServerError, r.JSON(map[string]string{
			"error": "Failed to update user",
		}))
	}

	// Hide password before sending response
	user.Password = ""

	return c.Render(http.StatusOK, r.JSON(user))
}

// DeleteUser deletes a user by ID
func DeleteUser(c buffalo.Context) error {
	// Get the user ID from URL params
	userID := c.Param("id")

	// Find the user by ID
	var user models.User
	err := models.DB.Find(&user, userID)
	if err != nil {
		return c.Render(http.StatusNotFound, r.JSON(map[string]string{
			"error": "User not found",
		}))
	}

	// Delete the user from DB
	err = models.DB.Destroy(&user)
	if err != nil {
		return c.Render(http.StatusInternalServerError, r.JSON(map[string]string{
			"error": "Failed to delete user",
		}))
	}

	return c.Render(http.StatusOK, r.JSON(map[string]string{
		"message": "User deleted successfully",
	}))
}

// UsersList - Get all users
func getAllUser(c buffalo.Context) error {
	var users []models.User

	// fetch all users from DB
	if err := models.DB.All(&users); err != nil {
		return c.Error(http.StatusInternalServerError, err)
	}

	return c.Render(http.StatusOK, r.JSON(users))
}
