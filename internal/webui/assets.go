package webui

import (
	"embed"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
)

const AssetVersion = "v1"

// Files contains the complete UI; runtime network access is never required.
//
//go:embed assets templates
var Files embed.FS

func AssetHandler() http.Handler {
	assets, err := fs.Sub(Files, "assets")
	if err != nil {
		panic(err)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if name == "." || strings.HasPrefix(name, "vendor/LICENSE") || name == "vendor/ASSETS.sha256" {
			http.NotFound(w, r)
			return
		}
		data, readErr := fs.ReadFile(assets, name)
		if readErr != nil {
			http.NotFound(w, r)
			return
		}
		contentType := mime.TypeByExtension(path.Ext(name))
		if contentType == "" {
			contentType = "application/octet-stream"
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write(data)
	})
}
