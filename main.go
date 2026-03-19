package main

import (
	"fmt"
	"os"

	api "blog/handlers"

	"github.com/joho/godotenv"
)

func init() {
	err := godotenv.Load()
	if err != nil {
		fmt.Println("Warning: .env file not found")
	}

	if err := api.EnsureStorage(); err != nil {
		fmt.Println("Storage init error:", err)
	}
}

func main() {
	api.RegisterRoutes()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	addr := ":" + port

	fmt.Printf("Server started at http://localhost:%s\n", port)

	if err := api.StartServer(addr); err != nil {
		fmt.Println("Server error:", err)
		os.Exit(1)
	}
}
