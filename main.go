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

	fmt.Println("Server started at http://localhost:8080")

	if err := api.StartServer(":8080"); err != nil {
		fmt.Println("Server error:", err)
		os.Exit(1)
	}

}
