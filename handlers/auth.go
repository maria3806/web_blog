package handlers

import (
	"blog/handlers/middleware"
	"blog/model"
	"crypto/rand"
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

func generateVerifyToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func HomeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	isLoggedIn := false

	if cookie, err := r.Cookie("auth_token"); err == nil && cookie.Value != "" {
		req, _ := http.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(cookie)

		rr := dummyResponseWriter{}
		called := false

		handler := middleware.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
			called = true
		})

		handler(rr, req)

		if called {
			isLoggedIn = true
		}
	}

	tmpl, err := parseTemplate("home.html")
	if err != nil {
		http.Error(w, "Template error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	data := struct {
		Error      string
		Success    string
		IsLoggedIn bool
	}{
		Error:      r.URL.Query().Get("error"),
		Success:    r.URL.Query().Get("success"),
		IsLoggedIn: isLoggedIn,
	}

	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

type dummyResponseWriter struct{}

func (dummyResponseWriter) Header() http.Header {
	return http.Header{}
}

func (dummyResponseWriter) Write(b []byte) (int, error) {
	return len(b), nil
}

func (dummyResponseWriter) WriteHeader(statusCode int) {}

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

	verifyToken, err := generateVerifyToken()
	if err != nil {
		http.Error(w, "Failed to generate verification token", http.StatusInternalServerError)
		return
	}

	user := model.User{
		Username:      username,
		Email:         email,
		PasswordHash:  hashPassword(password),
		RegisteredAt:  nowRegistrationTime(),
		PostCount:     0,
		Role:          "user",
		EmailVerified: false,
		VerifyToken:   verifyToken,
	}

	if err := saveUser(user); err != nil {
		http.Error(w, "Failed to save user", http.StatusInternalServerError)
		return
	}

	if err := sendVerificationEmail(user.Email, user.Username, user.VerifyToken); err != nil {
		http.Error(w, "Failed to prepare verification link", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/?success=check_console", http.StatusSeeOther)
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

	if !user.EmailVerified {
		http.Redirect(w, r, "/?error=email_not_verified", http.StatusSeeOther)
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

func VerifyEmailHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if token == "" {
		http.Redirect(w, r, "/?error=invalid_verification_token", http.StatusSeeOther)
		return
	}

	user, err := getUserByVerifyToken(token)
	if err != nil {
		http.Redirect(w, r, "/?error=invalid_verification_token", http.StatusSeeOther)
		return
	}

	user.EmailVerified = true
	user.VerifyToken = ""

	if err := saveUser(*user); err != nil {
		http.Error(w, "Failed to verify email", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/?success=email_verified", http.StatusSeeOther)
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

	adminUsername := os.Getenv("AUTH_USER")
	adminPassword := os.Getenv("AUTH_PASS")

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
