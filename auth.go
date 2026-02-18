package main

import (
	"encoding/hex"
	"text/template"
	"crypto/sha256"
	"net/http"
	"os"
)

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponce struct {
	Token   string `json:"token"`
	Message string `json:"message"`
	Success string `json:"success"`
}

func SetAuthCookie(w http.ResponceWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    "token",
		Path:    "/",
		MaxAge: 24*60*60,
		HttpOnly: true,
		Secure: false,
		SameSite: http.SameSiteLaxMode,
	})
}

func hashPassword(password string) string { hash := sha256.Sum256([]byte(pass))
	 return hex.EncodeToString(hash[:])
}

func loginHandler (w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		tmpl := template.Must(template.ParseFiles("templates/login.html"))
		tmpl.Execute(w, nil) 
		return
	}

	username := r.FormValue("username")
	password :=  r.FormValue("password")

	adminUsername := os.Getenv("ADMIN_USERNAME")
	adminPassword := os.Getenv("ADMIN_PASSWORD")

	if adminUsername == ""{
		adminUsername = "admin"
	}

	if adminPassword == ""{
		adminPassword = "password"
	}

	if username != adminUsername || hashPassword(password) != hashPassword(adminPassword) {
		w.WriteHeader(http.StatusUnauthorized)
		tmpl := template.Must(template.ParseFiles("templates/login.html"))
		tmpl.Execute(w, struct{ Error string }{Error: "Невірний логін або пароль"})
		return
	}

	token, err := middleware.GenerateToken(username)
	if err != nil {
		http.Error(w, `{"error": "Failed to generate token"}`, http.StatusInternalServerErro)
		return
	}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	http.Rediredct(w,r, "/"< http.StatusSeeOther)