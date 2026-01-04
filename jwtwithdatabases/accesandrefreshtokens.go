package jwtwithdatabases

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
)

type User struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

type MySQLInstance struct {
	DB *sql.DB
}

type RedisInstance struct {
	Client *redis.Client
}

type HybridHandler struct {
	Redis *RedisInstance
	Mysql *MySQLInstance
	Ctx   context.Context
}

// connect redis server
func ConnectRedis() (*RedisInstance, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr: os.Getenv("REDIS_ADDR"),
		DB:   0,
	})
	return &RedisInstance{Client: rdb}, nil
}

// connect mysql server
func ConnectMySQL() (*MySQLInstance, error) {
	db, err := sql.Open("mysql", os.Getenv("MYSQL_DSN"))
	if err != nil {
		panic(err)
	}
	return &MySQLInstance{DB: db}, nil
}

type Credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// JWT claims
type Claims struct {
	Email     string `json:"email"`
	TokenType string `json:"tokentype"` // "access token" or "refresh token"
	jwt.RegisteredClaims
}

const (
	accessTokenTTL  = 15 * time.Minute
	refreshTokenTTL = 7 * 24 * time.Hour
)

// generete access token
func GenerateAccessToken(email string) (string, error) {
	claims := &Claims{
		Email:     email,
		TokenType: "access",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(accessTokenTTL)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(SecretKey)
}

// Generate refresh tokens
func GenerateRefreshTokens(email string) (string, error) {
	claims := &Claims{
		TokenType: "refresh",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   email,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(refreshTokenTTL)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(SecretKey)
}

// Login (Generate JWT)
func Login(h *HybridHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var creds Credentials
		if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
			http.Error(w, "Failed to decode response", http.StatusInternalServerError)
			return
		}
		if creds.Email != "akash@gmail.com" || creds.Password != "Akash@123" {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}
		accesToken, _ := GenerateAccessToken(creds.Email)
		refreshToken, _ := GenerateRefreshTokens(creds.Email)

		h.Redis.Client.Set(h.Ctx, "refresh:"+refreshToken, creds.Email, refreshTokenTTL)

		json.NewEncoder(w).Encode(map[string]string{"access_token": accesToken, "refresh_token": refreshToken})
	}
}

// refresh
func Refresh(h *HybridHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			RefreshToken string `json:"refreshtoken"`
		}

		claims := &jwt.RegisteredClaims{}
		token, err := jwt.ParseWithClaims(body.RefreshToken, claims, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return SecretKey, nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "Invalid refresh tokens", http.StatusUnauthorized)
			return
		}
		email, err := h.Redis.Client.Get(h.Ctx, "refresh:"+body.RefreshToken).Result()
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		newAccessToken, _ := GenerateAccessToken(email)
		json.NewEncoder(w).Encode(map[string]string{"access_token": newAccessToken})
	}
}

// Logout
func Logout(h *HybridHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			RefreshToken string `json:"refreshtoken"`
		}
		json.NewDecoder(r.Body).Decode(&body)

		h.Redis.Client.Del(h.Ctx, "refresh:"+body.RefreshToken)
		w.Write([]byte("logged out!"))
	}
}

// Middleware
func JWTMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			http.Error(w, "Missing token", http.StatusUnauthorized)
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
			http.Error(w, "Invalid Token!", http.StatusUnauthorized)
			return
		}
		if claims.TokenType != "access" {
			http.Error(w, "Access token required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// validation
func Validate(users User) error {
	if strings.TrimSpace(users.Name) == "" {
		return fmt.Errorf("Name is invalid and empty!")
	}
	if strings.TrimSpace(users.Email) == "" {
		return fmt.Errorf("Email is invalid and empty!")
	}
	prefix := strings.TrimSuffix(users.Email, "@gmail.com")
	if prefix == "" {
		return fmt.Errorf("email must contains prefix before  @gmail.com")
	}
	if !strings.HasSuffix(users.Email, "@gmail.com") {
		return fmt.Errorf("email must contains @gmail.com ")
	}
	return nil
}

// create user

func (h *HybridHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	var users User
	if err := json.NewDecoder(r.Body).Decode(&users); err != nil {
		http.Error(w, "Failed to decode", http.StatusInternalServerError)
		return
	}

	if err := Validate(users); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	res, err := h.Mysql.DB.Exec("INSERT INTO users (name , email)VALUES (? , ?)", users.Name, users.Email)
	if err != nil {
		http.Error(w, "Failed to insert user", http.StatusInternalServerError)
		return
	}
	id, err := res.LastInsertId()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	users.ID = int(id)
	w.Header().Set("Content-type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(users)
}

// Get User
func (h *HybridHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	value, err := h.Redis.Client.Get(h.Ctx, id).Result()
	if err == nil {
		log.Println("cache hit!")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(value))
		return
	}
	log.Println("Cache miss Quering MySQL...")
	row := h.Mysql.DB.QueryRow("SELECT id , name , email FROM users WHERE id=?", id)

	var users User
	if err := row.Scan(&users.ID, &users.Name, &users.Email); err != nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	jsonData, err := json.Marshal(users)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	h.Redis.Client.Set(h.Ctx, id, jsonData, 10*time.Minute)

	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonData)
}

// Update user

func (h *HybridHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idStr := vars["id"]
	id, _ := strconv.Atoi(idStr)

	var users User
	if err := json.NewDecoder(r.Body).Decode(&users); err != nil {
		http.Error(w, "Failed to decode response", http.StatusInternalServerError)
		return
	}
	if err := Validate(users); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	res, err := h.Mysql.DB.Exec("UPDATE users SET name=?,email=? WHERE id=?", users.Name, users.Email, id)
	if err != nil {
		http.Error(w, "Failed to update user", http.StatusBadRequest)
		return
	}
	rows, err := res.RowsAffected()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if rows == 0 {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	users.ID = id
	jsondata, err := json.Marshal(&users)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
	h.Redis.Client.Set(h.Ctx, fmt.Sprint(users.ID), jsondata, 10*time.Minute)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsondata)
}

// Delete users

func (h *HybridHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	Idint, _ := strconv.Atoi(id)

	res, err := h.Mysql.DB.Exec("DELETE FROM users WHERE id=?", Idint)
	if err != nil {
		http.Error(w, "Failed to delete user", http.StatusInternalServerError)
		return
	}
	rows, err := res.RowsAffected()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if rows == 0 {
		http.Error(w, "user not found", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	w.Write([]byte("user deleted!"))

}

var SecretKey []byte

func Jwtwithdatabases() {
	godotenv.Load()

	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		log.Fatal("JWT_SECRET is not set or empty")
	}
	SecretKey = []byte(secret)

	redisinstance, err := ConnectRedis()
	if err != nil {
		log.Fatal(err)
	}
	mysqlinstance, err := ConnectMySQL()
	if err != nil {
		log.Fatal(err)
	}
	handler := &HybridHandler{Redis: redisinstance, Mysql: mysqlinstance, Ctx: context.Background()}

	r := mux.NewRouter()

	// Public route
	r.HandleFunc("/login", Login(handler)).Methods("POST")
	r.HandleFunc("/refresh", Refresh(handler)).Methods("POST")
	r.HandleFunc("/logout", Logout(handler)).Methods("POST")

	// Protected route
	api := r.PathPrefix("/api").Subrouter()
	api.Use(JWTMiddleware)

	api.HandleFunc("/users", handler.CreateUser).Methods("POST")
	api.HandleFunc("/users/{id}", handler.GetUser).Methods("GET")
	api.HandleFunc("/users/{id}", handler.UpdateUser).Methods("PUT")
	api.HandleFunc("/users/{id}", handler.DeleteUser).Methods("DELETE")

	fmt.Println("Server running on port:8080")
	http.ListenAndServe(":8080", r)

}
