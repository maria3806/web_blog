/*package main

import (
    "encoding/json"
    "fmt"
    "net/http"
    "os"
    "strconv"
    "strings"
    "time"
)

type Article struct {
    ID      int    `json:"id"`
    Title   string `json:"title"`
    Content string `json:"content"`
    Author  string `json:"author"`
    Date    string `json:"date"`
}

func ensureData() {
    os.Mkdir("articles", 0755)
    files, err := os.ReadDir("articles")
    if err != nil {
        fmt.Println("Error reading articles folder:", err)
        return
    }
    if len(files) > 0 {
        return
    }
    articles := []Article{
        {ID: 1, Title: "First article", Content: "Hello world", Author: "Alice", Date: "2025-01-01"},
        {ID: 2, Title: "Second article", Content: "Learning Go", Author: "Bob", Date: "2025-01-02"},
        {ID: 3, Title: "Third article", Content: "Simple JSON API", Author: "Alice", Date: "2025-01-03"},
    }
    for _, a := range articles {
        data, err := json.MarshalIndent(a, "", " ")
        if err != nil {
            fmt.Println("Error marshaling article:", err)
            continue
        }
        os.WriteFile(fmt.Sprintf("articles/%d.json", a.ID), data, 0644)
    }
}

//Create
func createArticle(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }
    var article Article
    if err := json.NewDecoder(r.Body).Decode(&article); err != nil {
        http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
        return
    }
    if article.Title == "" || article.Content == "" || article.Author == "" {
        http.Error(w, `{"error":"title and content required"}`, http.StatusBadRequest)
        return
    }
    if _, err := time.Parse("2006-01-02", article.Date); err != nil {
        http.Error(w, `{"error":"invalid date format"}`, http.StatusBadRequest)
        return
    }
    files, err := os.ReadDir("articles")
    if err != nil {
        http.Error(w, `{"error":"cannot read articles folder"}`, http.StatusInternalServerError)
        return
    }
    maxID := 0
    for _, f := range files {
        id, _ := strconv.Atoi(strings.TrimSuffix(f.Name(), ".json"))
        if id > maxID {
            maxID = id
        }
    }
    article.ID = maxID + 1
    data, err := json.MarshalIndent(article, "", " ")
    if err != nil {
        http.Error(w, `{"error":"cannot encode article"}`, http.StatusInternalServerError)
        return
    }
    err = os.WriteFile(fmt.Sprintf("articles/%d.json", article.ID), data, 0644)
    if err != nil {
        http.Error(w, `{"error":"cannot save article"}`, http.StatusInternalServerError)
        return
    }
    fmt.Println("Created article:", article.ID)
    w.WriteHeader(http.StatusCreated)
    w.Write(data)
}

func getArticles(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    idParam := r.URL.Query().Get("id")
    authorParam := r.URL.Query().Get("author")
    if idParam != "" {
        id, err := strconv.Atoi(idParam)
        if err != nil {
            http.Error(w, `{"error":"invalid id"}`, http.StatusBadRequest)
            return
        }
        data, err := os.ReadFile(fmt.Sprintf("articles/%d.json", id))
        if err != nil {
            http.Error(w, `{"error":"article not found"}`, http.StatusNotFound)
            return
        }
        w.Write(data)
        return
    }
    files, _ := os.ReadDir("articles")
    var articles []Article
    for _, f := range files {
        data, err := os.ReadFile("articles/" + f.Name())
        if err != nil {
            continue
        }
        var a Article
        if json.Unmarshal(data, &a) == nil {
            if authorParam == "" || strings.EqualFold(a.Author, authorParam) {
                articles = append(articles, a)
            }
        }
    }
    result, _ := json.MarshalIndent(articles, "", " ")
    w.Write(result)
}

//Update
func updateArticle(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    if r.Method != http.MethodPut {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }
    idStr := r.URL.Path[len("/articles/"):]
    id, err := strconv.Atoi(idStr)
    if err != nil {
        http.Error(w, `{"error":"invalid id"}`, http.StatusBadRequest)
        return
    }
    var article Article
    if err := json.NewDecoder(r.Body).Decode(&article); err != nil {
        http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
        return
    }
    article.ID = id
    data, _ := json.MarshalIndent(article, "", " ")
    if _, err := os.Stat(fmt.Sprintf("articles/%d.json", id)); err != nil {
        http.Error(w, `{"error":"article not found"}`, http.StatusNotFound)
        return
    }
    os.WriteFile(fmt.Sprintf("articles/%d.json", id), data, 0644)
    w.Write(data)
}

//Delete
func deleteArticle(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodDelete {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }
    idStr := r.URL.Path[len("/articles/"):]
    id, err := strconv.Atoi(idStr)
    if err != nil {
        http.Error(w, `{"error":"invalid id"}`, http.StatusBadRequest)
        return
    }
    if err := os.Remove(fmt.Sprintf("articles/%d.json", id)); err != nil {
        http.Error(w, `{"error":"article not found"}`, http.StatusNotFound)
        return
    }
    w.WriteHeader(http.StatusNoContent)
}

func main() {
    ensureData()
    http.HandleFunc("/articles", func(w http.ResponseWriter, r *http.Request) {
        if r.Method == http.MethodGet {
            getArticles(w, r)
        } else if r.Method == http.MethodPost {
            createArticle(w, r)
        } else {
            http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        }
    })
    http.HandleFunc("/articles/", func(w http.ResponseWriter, r *http.Request) {
        if r.Method == http.MethodPut {
            updateArticle(w, r)
        } else if r.Method == http.MethodDelete {
            deleteArticle(w, r)
        } else {
            http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        }
    })
    http.ListenAndServe(":8080", nil)
} */

package main

import (
	"fmt"
	"net/http"
)

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("→ Запит прийшов")
		next.ServeHTTP(w, r)
		fmt.Println("← Відповідь відправлено")
	})
}

func helloHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Привіт з handler-а!")
}

func main() {
	handler := http.HandlerFunc(helloHandler)
	// Обгортаємо handler у middleware
	http.Handle("/", loggingMiddleware(handler))
	fmt.Println("Сервер працює на :8080")
	http.ListenAndServe(":8080", nil)
}
