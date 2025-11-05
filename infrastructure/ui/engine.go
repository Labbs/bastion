package ui

import (
	"embed"
	"net/http"

	"github.com/gofiber/template/html/v2"
)

var (
	//go:embed templates/*
	templatesfs embed.FS
)

func InitEngine() *html.Engine {
	engine := html.NewFileSystem(http.FS(templatesfs), ".html")

	// Add custom functions to the engine

	return engine
}
