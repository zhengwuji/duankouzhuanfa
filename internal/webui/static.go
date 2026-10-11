package webui

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"embed"
	"encoding/hex"
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

// assetVersion is a short content hash of the front end, used to build a
// versioned URL for each asset.
//
// The asset paths are fixed (/app.js, /app.css), so without a version in the
// URL a browser has no way to tell one build's script from the next: it caches
// /app.js under a name that never changes. Combined with a long max-age that
// meant a browser which had opened the console once kept the previous build's
// script indefinitely, and an upgrade shipped a new panel that the operator
// never saw. A content hash is the honest cache key because it changes exactly
// when the bytes do.
var assetVersion = func() string {
	sub, err := fs.Sub(assetsFS, "assets")
	if err != nil {
		return "dev"
	}
	h := sha256.New()
	// The names are hashed with the content so that adding or removing a file
	// also changes the version.
	for _, name := range []string{"index.html", "app.css", "app.js"} {
		data, err := fs.ReadFile(sub, name)
		if err != nil {
			continue
		}
		h.Write([]byte(name))
		h.Write([]byte{0})
		h.Write(data)
	}
	return hex.EncodeToString(h.Sum(nil))[:12]
}()

// staticHandler serves the embedded front end, falling back to index.html so a
// client-side route deep link works on a refresh.
func (s *Server) staticHandler() http.Handler {
	sub, err := fs.Sub(assetsFS, "assets")
	if err != nil {
		// Only reachable if the embed directive and the directory disagree,
		// which is a build-time mistake rather than a runtime condition.
		panic("webui: embedded assets are missing: " + err.Error())
	}

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
			// An unknown API path is not a client-side route. Without this the
			// shell was served with a 200 for a mistyped endpoint, so a caller
			// (or a script) saw success and then failed parsing HTML as JSON —
			// and a probe could not tell a missing endpoint from a present one.
			if name == "api" || strings.HasPrefix(name, "api/") {
				writeError(w, http.StatusNotFound, "not_found", "unknown API endpoint: /%s", name)
				return
			}
			// Any other unknown path is a client-side route, so the shell is
			// served and the front end's router resolves it.
			serveIndex(w, r, sub)
			return
		}

		// The shell must never be cached: it is the one document that carries
		// the versioned asset URLs, so caching it would pin a browser to the
		// build it first saw.
		if name == "index.html" {
			serveIndex(w, r, sub)
			return
		}

		data, err := fs.ReadFile(sub, name)
		if err != nil {
			http.Error(w, "console asset is unavailable", http.StatusInternalServerError)
			return
		}

		// Only a URL that carries the current version may be cached forever.
		// The unversioned path stays revalidating, so a bookmarked or
		// hand-written /app.js still picks up a new build instead of being
		// served from cache for a year.
		if r.URL.Query().Get("v") == assetVersion {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		// The ETag is the content hash, so revalidation compares the bytes
		// rather than a timestamp that is the same for every build.
		w.Header().Set("Etag", `"`+assetVersion+`"`)
		http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(data))
	})
}

// serveIndex writes the single-page shell with versioned asset URLs.
func serveIndex(w http.ResponseWriter, r *http.Request, sub fs.FS) {
	data, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		http.Error(w, "console assets are unavailable", http.StatusInternalServerError)
		return
	}
	// Point the shell at the current build's assets. The replacements are
	// literal attribute strings so a missing or renamed reference leaves the
	// document intact rather than producing a broken URL.
	body := strings.ReplaceAll(string(data), `href="/app.css"`, `href="/app.css?v=`+assetVersion+`"`)
	body = strings.ReplaceAll(body, `src="/app.js"`, `src="/app.js?v=`+assetVersion+`"`)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Etag", `"`+assetVersion+`"`)
	http.ServeContent(w, r, "index.html", time.Time{}, strings.NewReader(body))
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
