package main

import (
	"embed"
	"html/template"
	"io/fs"
	"net/http"
	"path/filepath"
)

//go:embed templates/* static/*
var embeddedFiles embed.FS

// TemplateManager manages HTML templates with embedded filesystem support
type TemplateManager struct {
	templates map[string]*template.Template
}

// NewTemplateManager creates a new template manager and parses all templates
func NewTemplateManager() *TemplateManager {
	tm := &TemplateManager{
		templates: make(map[string]*template.Template),
	}

	// Parse templates from embedded filesystem
	tm.parseTemplates()

	return tm
}

// parseTemplates parses all template files from the embedded filesystem
func (tm *TemplateManager) parseTemplates() {
	// Parse each page template with the base layout
	pages := []string{"index", "admin"}
	for _, page := range pages {
		files := []string{
			"templates/layouts/base.html",
			filepath.Join("templates/pages", page+".html"),
			"templates/partials/header.html",
			"templates/partials/host-table.html",
			"templates/partials/host-row.html",
			"templates/partials/add-host.html",
			"templates/partials/range-list.html",
			"templates/partials/key-manager.html",
		}

		tmpl := template.New(page)
		for _, file := range files {
			content, err := fs.ReadFile(embeddedFiles, file)
			if err != nil {
				// File doesn't exist, skip
				continue
			}
			_, err = tmpl.Parse(string(content))
			if err != nil {
				// Log error but continue
				continue
			}
		}

		// Only store if we successfully parsed something
		if tmpl.Tree != nil {
			tm.templates[page] = tmpl
		}
	}

	// Parse partials independently (for htmx partial rendering)
	partials := []string{
		"host-table", "host-row", "add-host",
		"range-list", "key-manager",
	}
	for _, partial := range partials {
		path := filepath.Join("templates/partials", partial+".html")
		content, err := fs.ReadFile(embeddedFiles, path)
		if err != nil {
			// File doesn't exist yet, skip
			continue
		}

		tmpl, err := template.New(partial).Parse(string(content))
		if err != nil {
			continue
		}
		tm.templates[partial] = tmpl
	}
}

// Render executes a template with the given data and writes to the response
func (tm *TemplateManager) Render(w http.ResponseWriter, name string, data interface{}) error {
	tmpl, ok := tm.templates[name]
	if !ok {
		http.Error(w, "Template not found: "+name, http.StatusInternalServerError)
		return nil
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	return tmpl.Execute(w, data)
}

// GetEmbeddedFS returns the embedded filesystem for static file serving
func GetEmbeddedFS() fs.FS {
	staticFS, err := fs.Sub(embeddedFiles, "static")
	if err != nil {
		// Return empty FS if static directory doesn't exist yet
		return embeddedFiles
	}
	return staticFS
}
