package model

type User struct {
	Username     string `json:"username"`
	Email        string `json:"email"`
	PasswordHash string `json:"password_hash"`
	RegisteredAt string `json:"registered_at"`
	PostCount    int    `json:"post_count"`
	Role         string `json:"role"`

	EmailVerified bool   `json:"email_verified"`
	VerifyToken   string `json:"verify_token"`
}
