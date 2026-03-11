package handlers

import "net/http"

func RegisterRoutes() {
	http.HandleFunc("/", HomeHandler)
	http.HandleFunc("/articles", ArticlesHandler)
	http.HandleFunc("/notlogged", NotLoggedHandler)

	http.HandleFunc("/faq", FAQHandler)
	http.HandleFunc("/about", AboutHandler)

	http.HandleFunc("/account", AccountWithAuth())

	http.HandleFunc("/register", RegisterHandler)
	http.HandleFunc("/user-login", UserLoginHandler)
	http.HandleFunc("/admin-login", AdminLoginHandler)
	http.HandleFunc("/logout", LogoutHandler)
	http.HandleFunc("/verify", VerifyEmailHandler)

	http.HandleFunc("/dashboard-access", DashboardAccessHandler)
	http.HandleFunc("/dashboard", DashboardWithAdminAuth())

	http.HandleFunc("/new", CreateArticleWithAuth())
	http.HandleFunc("/edit", UpdateArticleWithAdminAuth())
	http.HandleFunc("/delete", DeleteArticleWithAdminAuth())

	http.Handle("/images/", http.StripPrefix("/images/", http.FileServer(http.Dir("images"))))
	http.Handle("/css/", http.StripPrefix("/css/", http.FileServer(http.Dir("HTML"))))
}

func StartServer(addr string) error {
	return http.ListenAndServe(addr, nil)
}
