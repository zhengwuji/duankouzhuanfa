package client

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// bufReader is the buffered reader the local HTTP proxy uses.
//
// It is an alias rather than a wrapper so the proxy code can call Buffered,
// Peek and Discard directly, which is what makes forwarding a request body
// that arrived in the same TCP segment as the headers correct.
type bufReader = bufio.Reader

func newBufReader(r io.Reader) *bufReader { return bufio.NewReaderSize(r, 32*1024) }

// httpRequest is the parsed form of a proxied HTTP request.
//
// The standard library's http.ReadRequest is not used for the origin-form
// rewrite because a proxy must preserve the exact header order and casing of
// what the client sent: some origin servers and a surprising number of
// middleboxes are sensitive to it, and the standard library normalises both.
type httpRequest struct {
	method     string
	rawURI     string
	proto      string
	target     string // authority for CONNECT, host:port for absolute form
	host       string
	headers    []headerLine
	bodyPrefix []byte
}

type headerLine struct {
	name  string
	value string
}

// readHTTPRequest parses a request line and headers from br.
func readHTTPRequest(br *bufReader) (*httpRequest, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return nil, fmt.Errorf("client: empty request line")
	}

	parts := strings.SplitN(line, " ", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("client: malformed request line %q", line)
	}
	req := &httpRequest{method: strings.ToUpper(parts[0]), rawURI: parts[1], proto: parts[2]}

	// A CONNECT request carries an authority in the request line; an absolute
	// URI carries the scheme and host; an origin-form request relies on the
	// Host header.
	switch {
	case req.method == http.MethodConnect:
		req.target = req.rawURI
	case strings.HasPrefix(req.rawURI, "http://"):
		rest := strings.TrimPrefix(req.rawURI, "http://")
		if i := strings.IndexAny(rest, "/?#"); i >= 0 {
			req.target = rest[:i]
		} else {
			req.target = rest
		}
	case strings.HasPrefix(req.rawURI, "https://"):
		rest := strings.TrimPrefix(req.rawURI, "https://")
		if i := strings.IndexAny(rest, "/?#"); i >= 0 {
			req.target = rest[:i]
		} else {
			req.target = rest
		}
	}

	for {
		h, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		h = strings.TrimRight(h, "\r\n")
		if h == "" {
			break
		}
		name, value, ok := strings.Cut(h, ":")
		if !ok {
			continue
		}
		req.headers = append(req.headers, headerLine{name: strings.TrimSpace(name), value: strings.TrimSpace(value)})
		if strings.EqualFold(name, "Host") {
			req.host = strings.TrimSpace(value)
		}
	}
	if req.target == "" {
		req.target = req.host
	}
	return req, nil
}

// originForm renders the request in origin form, which is what an origin
// server expects: the request line carries a path, not an absolute URI.
//
// Hop-by-hop headers are dropped because they describe the connection to the
// proxy, not to the origin; forwarding them would be a request-smuggling
// vector.
func (r *httpRequest) originForm() []byte {
	var buf bytes.Buffer

	path := r.rawURI
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		if i := strings.Index(path, "://"); i >= 0 {
			rest := path[i+3:]
			if j := strings.IndexAny(rest, "/?#"); j >= 0 {
				path = rest[j:]
			} else {
				path = "/"
			}
		}
	}
	if path == "" {
		path = "/"
	}

	proto := r.proto
	if proto == "" {
		proto = "HTTP/1.1"
	}
	fmt.Fprintf(&buf, "%s %s %s\r\n", r.method, path, proto)

	hasHost := false
	for _, h := range r.headers {
		if isHopByHop(h.name) {
			continue
		}
		if strings.EqualFold(h.name, "Host") {
			hasHost = true
		}
		fmt.Fprintf(&buf, "%s: %s\r\n", h.name, h.value)
	}
	if !hasHost && r.host != "" {
		fmt.Fprintf(&buf, "Host: %s\r\n", r.host)
	}
	buf.WriteString("\r\n")
	return buf.Bytes()
}

// hopByHop lists the headers that must not be forwarded.
var hopByHop = map[string]bool{
	"connection":          true,
	"proxy-connection":    true,
	"keep-alive":          true,
	"proxy-authenticate":  true,
	"proxy-authorization": true,
	"te":                  true,
	"trailer":             true,
	"transfer-encoding":   true,
	"upgrade":             true,
}

func isHopByHop(name string) bool { return hopByHop[strings.ToLower(name)] }

// writeSimpleResponse writes a minimal HTTP response with a text body.
func writeSimpleResponse(w io.Writer, code int, text string) {
	body := text + "\n"
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		code, http.StatusText(code), len(body), body)
}

// copyBuffered drains a buffered reader into dst.
func copyBuffered(dst net.Conn, br *bufReader) int64 {
	var total int64
	buf := make([]byte, 32*1024)
	for {
		n := br.Buffered()
		if n == 0 {
			return total
		}
		if n > len(buf) {
			n = len(buf)
		}
		chunk, err := br.Peek(n)
		if err != nil {
			return total
		}
		written, werr := dst.Write(chunk)
		total += int64(written)
		if werr != nil {
			return total
		}
		if _, err := br.Discard(written); err != nil {
			return total
		}
	}
}

// bcryptCompare verifies a bcrypt hash.
func bcryptCompare(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
