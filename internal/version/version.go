// Package version carries build identity for every PortTransit component.
//
// The values are overridable at link time:
//
//	go build -ldflags "-X porttransit/internal/version.Version=1.2.3"
package version

import (
	"fmt"
	"runtime"
	"time"
)

// Build identity. Version is the human-facing release string; the rest are
// stamped by the release pipeline and default to development values.
var (
	Version   = "1.0.0"
	Commit    = "dev"
	BuildTime = "unknown"
	Channel   = "stable"
)

// ProtocolVersion is the wire-format revision of the PortTransit preamble and
// control frames. Peers refuse to talk across a mismatch.
const ProtocolVersion uint8 = 1

// UserAgent is the default HTTP identity used by transports that speak HTTP
// (WebSocket, HTTP/2, gRPC, HTTPUpgrade) and by the deployment prober.
func UserAgent() string {
	return "PortTransit/" + Version
}

// String renders a single-line version banner.
func String() string {
	return fmt.Sprintf("PortTransit %s (%s/%s, %s, built %s, go %s)",
		Version, Channel, Commit, runtime.GOOS+"-"+runtime.GOARCH, BuildTime, runtime.Version())
}

// Short renders the compact form used in the Web GUI footer.
func Short() string {
	return fmt.Sprintf("v%s · %s/%s", Version, runtime.GOOS, runtime.GOARCH)
}

// BuildStamp returns the build time as a time.Time, or the zero time when the
// linker left the placeholder in place.
func BuildStamp() time.Time {
	t, err := time.Parse(time.RFC3339, BuildTime)
	if err != nil {
		return time.Time{}
	}
	return t
}
