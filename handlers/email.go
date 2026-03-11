package handlers

import "fmt"

func sendVerificationEmail(email, username, token string) error {
	verifyLink := fmt.Sprintf(
		"http://localhost:8080/verify?token=%s",
		token,
	)

	fmt.Println()
	fmt.Println("======================================")
	fmt.Println("EMAIL VERIFICATION REQUIRED")
	fmt.Println("User:", username)
	fmt.Println("Email:", email)
	fmt.Println("Open this link in browser:")
	fmt.Println(verifyLink)
	fmt.Println("======================================")
	fmt.Println()

	return nil
}
