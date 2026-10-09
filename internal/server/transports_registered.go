package server

// Blank-import every transport so the registry is populated for tests.
//
// The server package deliberately does not import the transports itself: it
// resolves them through transport.NewHandler, and the binary that wires it up
// (internal/app, cmd/porttransit) is what registers them. Tests that assert on
// a transport's shape — identityCapable reads the factory's NativeHeader field
// — therefore have to register them here, or the lookup would silently report
// "unknown transport" for everything and the assertions would be vacuous.
//
// The imports live in a non-test file because a _test.go file's blank imports
// would not be visible to the package's own tests in a way that is obvious;
// keeping it here makes the dependency explicit and greppable.
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
