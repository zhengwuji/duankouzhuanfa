package webui

import (
	"errors"
	"net/http"

	"porttransit/internal/config"
)

// Sentinel errors the resource handlers translate into HTTP status codes.
var (
	errNotFound      = errors.New("not found")
	errAlreadyExists = errors.New("already exists")
)

// inUseError reports a deletion that would break a dependent resource.
type inUseError struct {
	what string
}

func (e *inUseError) Error() string {
	return "still in use by " + e.what
}

// writeMutateError maps a mutate failure onto an HTTP response.
//
// The distinction that matters to the caller is whether the request was
// malformed (400, the operator should fix the form), referred to something
// absent (404), conflicted with existing state (409), or failed on the server
// (500, retrying may help).
func writeMutateError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such resource")
	case errors.Is(err, errAlreadyExists):
		writeError(w, http.StatusConflict, "already_exists", "a resource with that identifier already exists")
	default:
		var inUse *inUseError
		if errors.As(err, &inUse) {
			writeError(w, http.StatusConflict, "in_use", "cannot delete: the resource is %s", inUse.what)
			return
		}
		// A validation failure is the operator's to fix, so it is a 400 with
		// the full list of problems rather than an opaque 500.
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":  "the configuration was rejected",
			"code":   "invalid_config",
			"errors": splitProblems(err.Error()),
		})
	}
}

// marshalConfig serialises a configuration for the clone in mutate.
func marshalConfig(cfg *config.Config) ([]byte, error) {
	return jsonMarshal(cfg)
}
