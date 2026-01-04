package accessandrefreshtokens

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
)

type Credentials struct {
	Email    string
	Password string
}
type Claims struct {
	Email     string `json:"email,omitempty"`
	TokenType string `json:"token_type"` // "access token" and "refresh token"
	jwt.RegisteredClaims
}

const (
	AccessTokenTTL  = 15 * time.Minute
	RefreshTokenTTL = 7 * 24 * time.Hour
)

// Generate Access tokens
func GenerateAccessToken1(email string) (string, error) {
	claims := &Claims{
		Email:     email,
		TokenType: "access",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(AccessTokenTTL)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(SecretKey)
}

// Generate Refresh token
func GenerateRefreshToken1(email string) (string, error) {
	claims := &Claims{
		TokenType: "refresh",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   email,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(RefreshTokenTTL)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(SecretKey)
}

// Login
func Login1() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var creds Credentials
		if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
			http.Error(w, "failed to decode response", http.StatusInternalServerError)
			return
		}
		if creds.Email != "akashpaul4790@gmail.com" || creds.Password != "Akashpaul@479" {
			http.Error(w, "Invalid crediantials", http.StatusUnauthorized)
			return
		}
		accesstoken, _ := GenerateAccessToken1(creds.Email)
		refreshToken, _ := GenerateRefreshToken1(creds.Email)

		json.NewEncoder(w).Encode(map[string]string{"accesstoken": accesstoken, "refreshtoken": refreshToken})
	}
}

// Reftresh
func Refresh1() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			RefreshToken string `json:"refreshtoken"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "Invalid request body", http.StatusInternalServerError)
			return
		}
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(body.RefreshToken, claims, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return SecretKey, nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
			return
		}
		if claims.TokenType != "refresh" {
			http.Error(w, "refresh token required", http.StatusUnauthorized)
			return
		}
		NewAccessToken, _ := GenerateAccessToken1(claims.Subject)
		json.NewEncoder(w).Encode(map[string]string{"access_token": NewAccessToken})
	}
}

// Logout
func Logout1() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Refreshtoken string `json:"refreshtoken"`
		}
		json.NewDecoder(r.Body).Decode(&body)

		w.Write([]byte("logged out!"))
	}
}

// middleware
func JWTMiddleware1(next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")

		if auth == "" {
			http.Error(w, "missing token", http.StatusUnauthorized)
			return
		}
		tokenstr := strings.TrimPrefix(auth, "Bearer ")

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenstr, claims, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return SecretKey, nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
		if claims.TokenType != "access" {
			http.Error(w, "access token required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	}
}

var SecretKey []byte

// handlers
func Tokens() {

	godotenv.Load()

	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		log.Fatal("JWT_SECRET is not set or empty")
	}
	SecretKey = []byte(secret)

	http.HandleFunc("/login", Login1())
	http.HandleFunc("/refresh", Refresh1())
	http.HandleFunc("/logout", Logout1())

	fmt.Println("Server running on port:8080")
	http.ListenAndServe(":8080", nil)
}
