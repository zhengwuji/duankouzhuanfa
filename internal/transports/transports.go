// Package transports contains the concrete transport implementations.
//
// Every file here registers itself with the transport registry in its init
// function, so importing this package for its side effects makes all schemes
// available:
//
//	import _ "porttransit/internal/transports"
package transports

// The imports below are blank because each transport self-registers in init().
// Keeping them in one place means the binary can be built with a subset of
// schemes simply by editing this file, which is how the minimal relay build
// omits the heavier protocols.
import (
	_ "porttransit/internal/transports/direct"
	_ "porttransit/internal/transports/http"
	_ "porttransit/internal/transports/reality"
	_ "porttransit/internal/transports/shadowsocks"
	_ "porttransit/internal/transports/socks5"
	_ "porttransit/internal/transports/tls"
	_ "porttransit/internal/transports/trojan"
	_ "porttransit/internal/transports/vless"
	_ "porttransit/internal/transports/vmess"
	_ "porttransit/internal/transports/websocket"
)
