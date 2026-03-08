package handlers

import (
	"blog/handlers/middleware"
	"blog/model"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"strings"
)

func SetAuthCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    token,
		Path:     "/",
		MaxAge:   24 * 60 * 60,
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	})
}

func hashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}

func HomeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tmpl, err := parseTemplate("home.html")
	if err != nil {
		http.Error(w, "Template error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	data := struct {
		Error string
	}{
		Error: r.URL.Query().Get("error"),
	}

	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	email := strings.TrimSpace(r.FormValue("email"))
	username := strings.TrimSpace(r.FormValue("username"))
	password := strings.TrimSpace(r.FormValue("password"))

	if email == "" || username == "" || password == "" {
		http.Redirect(w, r, "/?error=fill_all_fields", http.StatusSeeOther)
		return
	}

	if userExistsByUsername(username) {
		http.Redirect(w, r, "/?error=username_exists", http.StatusSeeOther)
		return
	}

	if userExistsByEmail(email) {
		http.Redirect(w, r, "/?error=email_exists", http.StatusSeeOther)
		return
	}

	user := model.User{
		Username:     username,
		Email:        email,
		PasswordHash: hashPassword(password),
		RegisteredAt: nowRegistrationTime(),
		PostCount:    0,
		Role:         "user",
	}

	if err := saveUser(user); err != nil {
		http.Error(w, "Failed to save user", http.StatusInternalServerError)
		return
	}

	token, err := middleware.GenerateToken(user.Username, user.Role)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	SetAuthCookie(w, token)
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}

func UserLoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	password := strings.TrimSpace(r.FormValue("password"))

	user, err := getUserByUsername(username)
	if err != nil {
		http.Redirect(w, r, "/?error=user_not_found", http.StatusSeeOther)
		return
	}

	if user.PasswordHash != hashPassword(password) {
		http.Redirect(w, r, "/?error=wrong_password", http.StatusSeeOther)
		return
	}

	token, err := middleware.GenerateToken(user.Username, user.Role)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	SetAuthCookie(w, token)
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}

func DashboardAccessHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Redirect(w, r, "/dashboard-access", http.StatusSeeOther)
		return
	}

	tmpl, err := parseTemplate("dashboardAccess.html")
	if err != nil {
		http.Error(w, "Template error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	data := struct {
		Error string
	}{
		Error: r.URL.Query().Get("error"),
	}

	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func AdminLoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/dashboard-access", http.StatusSeeOther)
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	password := strings.TrimSpace(r.FormValue("password"))

	adminUsername := os.Getenv("ADMIN_USERNAME")
	adminPassword := os.Getenv("ADMIN_PASSWORD")

	if adminUsername == "" {
		adminUsername = "admin"
	}
	if adminPassword == "" {
		adminPassword = "password"
	}

	if username != adminUsername || password != adminPassword {
		http.Redirect(w, r, "/dashboard-access?error=invalid_admin_credentials", http.StatusSeeOther)
		return
	}

	token, err := middleware.GenerateToken(username, "admin")
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	SetAuthCookie(w, token)
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	middleware.ClearAuthCookie(w)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
