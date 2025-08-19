package actions

import (
	"login/models"
	"strconv"

	"os"
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
