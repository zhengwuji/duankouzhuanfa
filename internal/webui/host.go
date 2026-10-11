package webui

import (
	"net/http"

	"porttransit/internal/hostmon"
)

// The host resource endpoint.
//
// It is a separate endpoint rather than another field on /api/v1/status for two
// reasons. The dashboard polls it on its own, slower cadence than the counters
// it shares a page with, and a host that cannot be sampled at all returns a
// snapshot that says so — which is a different shape from the status document
// and would otherwise have to be special-cased by every consumer of it.

// hostResponse is the JSON document the dashboard renders.
type hostResponse struct {
	hostmon.Snapshot
	// Available is false when this build or this host has no collector, so the
	// panel can be hidden without the client having to interpret Supported.
	Available bool `json:"available"`
	// PollSeconds is how often the client should ask again. The server owns
	// this number so the cadence follows the configured sampling interval
	// instead of a constant duplicated in the front end.
	PollSeconds float64 `json:"pollSeconds"`
}

// handleHost reports the state of the machine this console runs on.
//
// It never fails on a host that cannot be sampled: the snapshot carries the
// reason, and the console shows an explanation rather than an error, because a
// missing host panel is not a fault in the request.
func (s *Server) handleHost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "host status requires GET")
		return
	}
	if s.host == nil {
		// The monitor is absent for two different reasons, and saying the wrong
		// one sends the operator looking in the wrong place. "This platform has
		// no collector" is a dead end; "collection is switched off" has a fix
		// in the configuration.
		reason := "主机资源采集未启用"
		if s.cfg != nil && !s.cfg.Host.Enabled {
			reason = "主机资源采集已在配置中关闭（host.enabled = false）"
		}
		writeJSON(w, http.StatusOK, hostResponse{
			Available: false,
			Snapshot:  hostmon.Snapshot{Reason: reason},
		})
		return
	}

	snap := s.host.Snapshot()
	// The client polls at the sampling period, but never faster than a second:
	// the panel is a display, and a browser refreshing it faster than the
	// sampler produces values would only show the same reading repeatedly.
	poll := snap.Interval
	if poll < 1 {
		poll = 1
	}
	writeJSON(w, http.StatusOK, hostResponse{
		Snapshot:    snap,
		Available:   snap.Supported,
		PollSeconds: poll,
	})
}
