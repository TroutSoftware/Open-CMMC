package fbhttp

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"

	scan "github.com/filebrowser/filebrowser/v2/cmmc/scan"
	libErrors "github.com/filebrowser/filebrowser/v2/errors"
	imgErrors "github.com/filebrowser/filebrowser/v2/img"
)

// logSafe strips CR/LF from a string before it is interpolated into a
// log line. Username, resource path, and other user-controlled values
// flow into log.Printf across several handlers — an attacker who can
// influence those fields could otherwise inject forged lines into the
// log stream (CWE-117). Keep the function tight: no truncation, no
// HTML/ANSI handling — just the characters that break line-oriented
// log parsers.
func logSafe(s string) string {
	if s == "" {
		return s
	}
	r := strings.NewReplacer("\r", "\\r", "\n", "\\n")
	return r.Replace(s)
}

func renderJSON(w http.ResponseWriter, _ *http.Request, data interface{}) (int, error) {
	marsh, err := json.Marshal(data)

	if err != nil {
		return http.StatusInternalServerError, err
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if _, err := w.Write(marsh); err != nil {
		return http.StatusInternalServerError, err
	}

	return 0, nil
}

func errToStatus(err error) int {
	var rejected *scan.RejectedError
	switch {
	case err == nil:
		return http.StatusOK
	case errors.As(err, &rejected):
		// CMMC 3.14.2: infected payload → 422 Unprocessable Entity.
		// We don't want 400 (caller's request was syntactically
		// fine) or 403 (not an authz failure). 422 is the HTTP
		// canon for "we understood and refuse to persist."
		return http.StatusUnprocessableEntity
	case errors.Is(err, scan.ErrUnavailable):
		// Scanner backend down in Required mode. 503 so the client
		// can retry once operations fixes clamd.
		return http.StatusServiceUnavailable
	case os.IsPermission(err):
		return http.StatusForbidden
	case os.IsNotExist(err), errors.Is(err, libErrors.ErrNotExist):
		return http.StatusNotFound
	case os.IsExist(err), errors.Is(err, libErrors.ErrExist):
		return http.StatusConflict
	case errors.Is(err, libErrors.ErrPermissionDenied):
		return http.StatusForbidden
	case errors.Is(err, libErrors.ErrInvalidRequestParams):
		return http.StatusBadRequest
	case errors.Is(err, libErrors.ErrRootUserDeletion):
		return http.StatusForbidden
	case errors.Is(err, imgErrors.ErrImageTooLarge):
		return http.StatusRequestEntityTooLarge
	default:
		return http.StatusInternalServerError
	}
}

// This is an adaptation if http.StripPrefix in which we don't
// return 404 if the page doesn't have the needed prefix.
func stripPrefix(prefix string, h http.Handler) http.Handler {
	if prefix == "" || prefix == "/" {
		return h
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, prefix)
		rp := strings.TrimPrefix(r.URL.RawPath, prefix)

		// If the path is exactly the prefix (no trailing slash), redirect to
		// the prefix with a trailing slash so the router receives "/" instead
		// of "", which would otherwise cause a redirect to the site root.
		if p == "" {
			http.Redirect(w, r, prefix+"/", http.StatusMovedPermanently)
			return
		}

		r2 := new(http.Request)
		*r2 = *r
		r2.URL = new(url.URL)
		*r2.URL = *r.URL
		r2.URL.Path = p
		r2.URL.RawPath = rp
		h.ServeHTTP(w, r2)
	})
}
