package handlers

import (
	"path/filepath"
	"text/template"
)

// "Мінус — storage.go змішує відповідальності (парсинг шаблонів + файлові операції)"
// Тепер storage.go відповідає тільки за операції з файлами, парсінг шаблонів винесений в renderer.go

func parseTemplate(templateName string) (*template.Template, error) {
	return template.ParseFiles(filepath.Join("HTML", templateName))
}
