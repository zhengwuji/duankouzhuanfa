package webui

import (
	"bytes"
	"compress/gzip"
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"
)

// The console's front end is embedded in the binary.
//
// Embedding rather than serving from disk is what lets the installer drop a
// single executable on a host and have the console work immediately, with no
// web root to keep in sync and no chance of a stale asset being served after
// an upgrade. It also means the management interface has no filesystem
// dependency that could be used to read arbitrary files.
//
//go:embed assets
var assetsFS embed.FS

// assetModTime is a fixed timestamp used for cache validators.
//
// The assets are compiled into the binary, so their content only changes when
// the binary does. A constant timestamp is therefore honest, and it lets the
// browser cache aggressively without ever serving a stale asset for a given
// build.
var assetModTime = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

// staticHandler serves the embedded front end, falling back to index.html so a
// client-side route deep link works on a refresh.
func (s *Server) staticHandler() http.Handler {
	sub, err := fs.Sub(assetsFS, "assets")
	if err != nil {
		// Only reachable if the embed directive and the directory disagree,
		// which is a build-time mistake rather than a runtime condition.
		panic("webui: embedded assets are missing: " + err.Error())
	}
	fileServer := http.FileServer(http.FS(sub))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "static assets are read-only")
			return
		}

		name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if name == "" || name == "." {
			name = "index.html"
		}

		if _, err := fs.Stat(sub, name); err != nil {
			// An unknown path is a client-side route, so the shell is served
			// and the front end's router resolves it.
			serveIndex(w, r, sub)
			return
		}

		// A fingerprinted asset can be cached forever; the shell must not be,
		// or an upgrade would keep serving the previous build's script.
		if strings.HasPrefix(name, "app.") || strings.Contains(name, ".") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		http.ServeContent(w, r, name, assetModTime, mustOpen(sub, name))
		_ = fileServer
	})
}

// serveIndex writes the single-page shell.
func serveIndex(w http.ResponseWriter, r *http.Request, sub fs.FS) {
	data, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		http.Error(w, "console assets are unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeContent(w, r, "index.html", assetModTime, bytes.NewReader(data))
}

// mustOpen reads an embedded file into memory.
//
// The assets are small enough that reading them per request is cheaper than
// the bookkeeping needed to cache them, and it keeps the handler free of a
// shared mutable cache that a concurrent request could race.
func mustOpen(sub fs.FS, name string) *bytes.Reader {
	data, err := fs.ReadFile(sub, name)
	if err != nil {
		return bytes.NewReader(nil)
	}
	return bytes.NewReader(data)
}

// gzipIfAccepted is reserved for deployments that serve the console over a
// slow link. It is currently unused because the embedded assets are already
// small enough that the CPU cost of compressing each response would exceed the
// bytes saved; the helper is kept so enabling it later is a one-line change.
func gzipIfAccepted(w http.ResponseWriter, r *http.Request, body []byte) ([]byte, bool) {
	if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") || len(body) < 1024 {
		return body, false
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(body); err != nil {
		return body, false
	}
	if err := zw.Close(); err != nil {
		return body, false
	}
	w.Header().Set("Content-Encoding", "gzip")
	w.Header().Add("Vary", "Accept-Encoding")
	return buf.Bytes(), true
}
