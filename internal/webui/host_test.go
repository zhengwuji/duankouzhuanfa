package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"porttransit/internal/config"
	"porttransit/internal/hostmon"
	"porttransit/internal/logx"
)

// The host endpoint backs the resource panel on the dashboard. Its failure
// modes are all about honesty: a panel that cannot be filled must say why
// rather than showing zeroes, and it must not claim the wrong reason, because
// "this platform has no collector" and "collection is switched off" send the
// operator to completely different places.

// TestHostEndpointRequiresGET keeps the endpoint read-only. It is a status
// view, so anything else is a client bug worth reporting plainly.
func TestHostEndpointRequiresGET(t *testing.T) {
	s := &Server{cfg: &config.Config{}, log: logx.Discard()}

	rec := httptest.NewRecorder()
	s.handleHost(rec, httptest.NewRequest(http.MethodPost, "/api/v1/host", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST returned %d, want 405", rec.Code)
	}
}

// TestHostEndpointDistinguishesDisabledFromUnsupported pins the two reasons a
// missing panel can have.
//
// Telling an operator their platform is unsupported when they simply set
// host.enabled to false is a dead end: there is nothing to fix, and the real
// fix is a configuration key they would never think to look at.
func TestHostEndpointDistinguishesDisabledFromUnsupported(t *testing.T) {
	cases := []struct {
		name   string
		host   *config.HostConfig
		expect string
	}{
		{
			name:   "switched off in the configuration",
			host:   &config.HostConfig{Enabled: false},
			expect: "host.enabled",
		},
		{
			name:   "no collector was built",
			host:   &config.HostConfig{Enabled: true},
			expect: "未启用",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{
				cfg: &config.Config{Host: *tc.host},
				log: logx.Discard(),
			}
			rec := httptest.NewRecorder()
			s.handleHost(rec, httptest.NewRequest(http.MethodGet, "/api/v1/host", nil))

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200: a host that cannot be sampled is not a "+
					"request failure", rec.Code)
			}
			var got hostResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if got.Available {
				t.Error("Available = true with no monitor, so the panel would render as if " +
					"it had data")
			}
			if !strings.Contains(got.Reason, tc.expect) {
				t.Errorf("Reason = %q, want it to mention %q", got.Reason, tc.expect)
			}
		})
	}
}

// TestHostEndpointNeverPollsFasterThanItSamples proves the cadence handed to
// the browser is bounded.
//
// The front end polls at whatever pollSeconds says, so a zero or a fraction
// would turn the dashboard into a request loop against a protected endpoint —
// the sampler could not keep up, and every tick would return the same reading.
func TestHostEndpointNeverPollsFasterThanItSamples(t *testing.T) {
	cases := []struct {
		name     string
		interval time.Duration
	}{
		{"a monitor that has not sampled yet", 0},
		{"a sub-second interval", 200 * time.Millisecond},
		{"a normal interval", 5 * time.Second},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{
				cfg:  &config.Config{},
				log:  logx.Discard(),
				host: hostmon.New(hostmon.Options{Interval: tc.interval}),
			}
			rec := httptest.NewRecorder()
			s.handleHost(rec, httptest.NewRequest(http.MethodGet, "/api/v1/host", nil))

			var got hostResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if got.PollSeconds < 1 {
				t.Errorf("PollSeconds = %v, want at least 1: the browser would poll faster "+
					"than the sampler produces values", got.PollSeconds)
			}
		})
	}
}

// TestHostEndpointAvailabilityFollowsTheSnapshot proves Available is derived
// from the snapshot rather than assumed, so the two can never disagree.
func TestHostEndpointAvailabilityFollowsTheSnapshot(t *testing.T) {
	// A monitor that was never started has not read anything, so it is not
	// available and must not claim to be.
	s := &Server{
		cfg:  &config.Config{},
		log:  logx.Discard(),
		host: hostmon.New(hostmon.Options{}),
	}
	rec := httptest.NewRecorder()
	s.handleHost(rec, httptest.NewRequest(http.MethodGet, "/api/v1/host", nil))

	var got hostResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Available != got.Supported {
		t.Errorf("Available = %v but Supported = %v; the panel trusts Available, so the "+
			"two must agree", got.Available, got.Supported)
	}
}
