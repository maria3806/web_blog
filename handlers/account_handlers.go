package handlers

import (
	"net/http"

	"blog/handlers/middleware"
)

type AccountPageData struct {
	Username     string
	Email        string
	RegisteredAt string
	PostCount    int
	PasswordMask string
	Role         string
}

func AccountHandler(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetUserFromContext(r.Context())
	if claims == nil {
		http.Redirect(w, r, "/notlogged", http.StatusSeeOther)
		return
	}

	data := AccountPageData{
		Username:     claims.Username,
		Email:        "admin@lemoniq.local",
		RegisteredAt: "admin session",
		PostCount:    0,
		PasswordMask: "••••••••",
		Role:         claims.Role,
	}

	if claims.Role != "admin" {
		user, err := getUserByUsername(claims.Username)
		if err != nil {
			http.Redirect(w, r, "/notlogged", http.StatusSeeOther)
			return
		}

		data.Username = user.Username
		data.Email = user.Email
		data.RegisteredAt = user.RegisteredAt
		data.PostCount = user.PostCount
		data.PasswordMask = "••••••••"
		data.Role = user.Role
	}

	tmpl, err := parseTemplate("account.html")
	if err != nil {
		http.Error(w, "Template error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func AccountWithAuth() http.HandlerFunc {
	return middleware.RequireAuth(AccountHandler)
}
