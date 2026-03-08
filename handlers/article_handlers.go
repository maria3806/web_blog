package handlers

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"blog/handlers/middleware"
	"blog/model"
)

type ArticlesPageData struct {
	Articles []model.Article
}

func ArticlesHandler(w http.ResponseWriter, r *http.Request) {
	articles := getArticlesList()

	tmpl, err := parseTemplate("articles.html")
	if err != nil {
		http.Error(w, "Template error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	data := ArticlesPageData{
		Articles: articles,
	}

	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func NotLoggedHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, err := parseTemplate("notlogged.html")
	if err != nil {
		http.Error(w, "Template error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := tmpl.Execute(w, nil); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func DashboardHandler(w http.ResponseWriter, r *http.Request) {
	articles := getArticlesList()

	tmpl, err := parseTemplate("dashboard.html")
	if err != nil {
		http.Error(w, "Template error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := tmpl.Execute(w, articles); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func CreateArticleHandler(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetUserFromContext(r.Context())
	if claims == nil {
		http.Redirect(w, r, "/notlogged", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodGet {
		tmpl, err := parseTemplate("newArticle.html")
		if err != nil {
			http.Error(w, "Template error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if err := tmpl.Execute(w, nil); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	title := strings.TrimSpace(r.FormValue("title"))
	content := strings.TrimSpace(r.FormValue("content"))
	published := strings.TrimSpace(r.FormValue("date"))
	image := strings.TrimSpace(r.FormValue("image"))

	if title == "" || content == "" {
		http.Error(w, "Title and content are required", http.StatusBadRequest)
		return
	}

	if published == "" {
		published = time.Now().Format("2006-01-02")
	}

	if image == "" {
		image = "/images/header.jpg"
	}

	newArticle := model.Article{
		ID:        nextArticleID(),
		Title:     title,
		Content:   content,
		Published: published,
		Author:    claims.Username,
		Image:     image,
	}

	if err := saveArticle(newArticle); err != nil {
		http.Error(w, "Failed to save article", http.StatusInternalServerError)
		return
	}

	if claims.Role != "admin" {
		user, err := getUserByUsername(claims.Username)
		if err == nil {
			user.PostCount++
			_ = saveUser(*user)
		}
	}

	http.Redirect(w, r, "/articles", http.StatusSeeOther)
}

func UpdateArticleHandler(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid article ID", http.StatusBadRequest)
		return
	}

	article, err := getArticleByID(id)
	if err != nil {
		http.Error(w, "Article not found", http.StatusNotFound)
		return
	}

	if r.Method == http.MethodGet {
		tmpl, err := parseTemplate("updateArticle.html")
		if err != nil {
			http.Error(w, "Template error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if err := tmpl.Execute(w, article); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	title := strings.TrimSpace(r.FormValue("title"))
	content := strings.TrimSpace(r.FormValue("content"))
	published := strings.TrimSpace(r.FormValue("date"))
	image := strings.TrimSpace(r.FormValue("image"))

	if title == "" || content == "" {
		http.Error(w, "Title and content are required", http.StatusBadRequest)
		return
	}

	article.Title = title
	article.Content = content

	if published != "" {
		article.Published = published
	}

	if image != "" {
		article.Image = image
	}

	if err := saveArticle(*article); err != nil {
		http.Error(w, "Failed to update article", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func DeleteArticleHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	idStr := r.URL.Query().Get("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid article ID", http.StatusBadRequest)
		return
	}

	article, _ := getArticleByID(id)

	if err := deleteArticleByID(id); err != nil {
		http.Error(w, "Failed to delete article", http.StatusInternalServerError)
		return
	}

	if article != nil && article.Author != "" && article.Author != "system" {
		user, err := getUserByUsername(article.Author)
		if err == nil && user.PostCount > 0 {
			user.PostCount--
			_ = saveUser(*user)
		}
	}

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func CreateArticleWithAuth() http.HandlerFunc {
	return middleware.RequireAuth(CreateArticleHandler)
}

func UpdateArticleWithAdminAuth() http.HandlerFunc {
	return middleware.RequireAdmin(UpdateArticleHandler)
}

func DashboardWithAdminAuth() http.HandlerFunc {
	return middleware.RequireAdmin(DashboardHandler)
}

func DeleteArticleWithAdminAuth() http.HandlerFunc {
	return middleware.RequireAdmin(DeleteArticleHandler)
}
