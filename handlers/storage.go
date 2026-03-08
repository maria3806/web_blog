package handlers

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"
	"time"

	"blog/model"
)

const (
	articlesDir = "articles"
	usersDir    = "users"
)

func EnsureStorage() error {
	if err := os.MkdirAll(articlesDir, 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(usersDir, 0755); err != nil {
		return err
	}
	return ensureBaseArticles()
}

func ensureBaseArticles() error {
	baseArticles := []model.Article{
		{
			ID:        1,
			Title:     "What's New?",
			Content:   "Welcome to our mini creative space. Here, we share our latest thoughts and ideas. To share your own thoughts, simply click the New Article button below. But first, you need to be logged in.",
			Published: "2026-03-07",
			Author:    "system",
			Image:     "/images/header.jpg",
		},
		{
			ID:        2,
			Title:     "Wassup",
			Content:   "Bon appétit to me..",
			Published: "2026-03-07",
			Author:    "system",
			Image:     "/images/header2.jpg",
		},
		{
			ID:        3,
			Title:     "...",
			Content:   "okay i will use post method",
			Published: "2026-03-07",
			Author:    "system",
			Image:     "/images/header3.png",
		},
	}

	for _, article := range baseArticles {
		filePath := filepath.Join(articlesDir, fmt.Sprintf("article%d.json", article.ID))
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			if err := saveArticle(article); err != nil {
				return err
			}
		}
	}

	return nil
}

func parseTemplate(templateName string) (*template.Template, error) {
	return template.ParseFiles(filepath.Join("HTML", templateName))
}

func articleFilePath(id int) string {
	return filepath.Join(articlesDir, fmt.Sprintf("article%d.json", id))
}

func saveArticle(article model.Article) error {
	file, err := os.Create(articleFilePath(article.ID))
	if err != nil {
		return err
	}
	defer file.Close()

	enc := json.NewEncoder(file)
	enc.SetIndent("", "  ")
	return enc.Encode(article)
}

func getArticlesList() []model.Article {
	files, err := os.ReadDir(articlesDir)
	if err != nil {
		return nil
	}

	var articles []model.Article
	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".json") {
			continue
		}

		data, err := os.ReadFile(filepath.Join(articlesDir, f.Name()))
		if err != nil {
			continue
		}

		var a model.Article
		if err := json.Unmarshal(data, &a); err != nil {
			continue
		}
		articles = append(articles, a)
	}

	sort.Slice(articles, func(i, j int) bool {
		return articles[i].ID < articles[j].ID
	})

	return articles
}

func getArticleByID(id int) (*model.Article, error) {
	data, err := os.ReadFile(articleFilePath(id))
	if err != nil {
		return nil, err
	}

	var a model.Article
	if err := json.Unmarshal(data, &a); err != nil {
		return nil, err
	}

	return &a, nil
}

func deleteArticleByID(id int) error {
	return os.Remove(articleFilePath(id))
}

func nextArticleID() int {
	articles := getArticlesList()
	maxID := 0
	for _, a := range articles {
		if a.ID > maxID {
			maxID = a.ID
		}
	}
	return maxID + 1
}

func safeUsernameFile(username string) string {
	name := strings.TrimSpace(strings.ToLower(username))
	name = strings.ReplaceAll(name, " ", "_")
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.ReplaceAll(name, "\\", "_")
	return filepath.Join(usersDir, name+".json")
}

func saveUser(user model.User) error {
	file, err := os.Create(safeUsernameFile(user.Username))
	if err != nil {
		return err
	}
	defer file.Close()

	enc := json.NewEncoder(file)
	enc.SetIndent("", "  ")
	return enc.Encode(user)
}

func getUserByUsername(username string) (*model.User, error) {
	data, err := os.ReadFile(safeUsernameFile(username))
	if err != nil {
		return nil, err
	}

	var user model.User
	if err := json.Unmarshal(data, &user); err != nil {
		return nil, err
	}
	return &user, nil
}

func userExistsByUsername(username string) bool {
	_, err := getUserByUsername(username)
	return err == nil
}

func userExistsByEmail(email string) bool {
	files, err := os.ReadDir(usersDir)
	if err != nil {
		return false
	}

	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".json") {
			continue
		}

		data, err := os.ReadFile(filepath.Join(usersDir, f.Name()))
		if err != nil {
			continue
		}

		var user model.User
		if err := json.Unmarshal(data, &user); err != nil {
			continue
		}

		if strings.EqualFold(strings.TrimSpace(user.Email), strings.TrimSpace(email)) {
			return true
		}
	}

	return false
}

func nowRegistrationTime() string {
	return time.Now().Format("2006-01-02 15:04")
}
