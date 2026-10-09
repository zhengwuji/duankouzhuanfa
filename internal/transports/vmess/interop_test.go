package vmess

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"porttransit/internal/cryptox"
	"porttransit/internal/transport"
)

// The cross-checks below are driven by an external Python implementation
// (vmess_interop.py) written from the v2fly specification with different crypto
// libraries. They are skipped unless VMESS_INTEROP_DIR names a directory the
// harness has populated, so the package still tests cleanly on its own.

func interopDir(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("VMESS_INTEROP_DIR")
	if dir == "" {
		t.Skip("VMESS_INTEROP_DIR is not set")
	}
	return dir
}

// TestInteropParsePythonRequest feeds the relay a request header produced by the
// Python implementation and checks the decoded target.
func TestInteropParsePythonRequest(t *testing.T) {
	dir := interopDir(t)
	blob, err := os.ReadFile(dir + "/vmess_py_request.bin")
	if err != nil {
		t.Fatalf("read python request: %v", err)
	}

	uuid := cryptox.MustParseUUID("b831381d-6324-4d53-ad4f-8cda48b30811")
	h, err := readRequestHeader(&sliceConn{data: blob}, CmdKey(uuid))
	if err != nil {
		t.Fatalf("readRequestHeader: %v", err)
	}
	if h.Address != "target.example:8443" {
		t.Fatalf("address = %q, want target.example:8443", h.Address)
	}
	if h.Command != cmdTCP {
		t.Fatalf("command = %#x, want 0x01", h.Command)
	}
	if h.Security != SecurityChaCha20Poly1305 {
		t.Fatalf("security = %v, want chacha20-poly1305", h.Security)
	}
	if h.Option != 0 {
		t.Fatalf("option = %#x, want 0", h.Option)
	}
	if h.Padding > maxPadding {
		t.Fatalf("padding = %d, want <= %d", h.Padding, maxPadding)
	}
}

// sliceConn adapts a byte slice to io.Reader for readRequestHeader.
type sliceConn struct {
	data []byte
	off  int
}

func (s *sliceConn) Read(p []byte) (int, error) {
	if s.off >= len(s.data) {
		return 0, io.EOF
	}
	n := copy(p, s.data[s.off:])
	s.off += n
	return n, nil
}

func (s *sliceConn) Write(p []byte) (int, error)      { return 0, io.ErrClosedPipe }
func (s *sliceConn) Close() error                     { return nil }
func (s *sliceConn) LocalAddr() net.Addr              { return nil }
func (s *sliceConn) RemoteAddr() net.Addr             { return nil }
func (s *sliceConn) SetDeadline(time.Time) error      { return nil }
func (s *sliceConn) SetReadDeadline(time.Time) error  { return nil }
func (s *sliceConn) SetWriteDeadline(time.Time) error { return nil }

// TestInteropEmitGoRequest writes a request header this package produces so the
// Python implementation can parse it.
func TestInteropEmitGoRequest(t *testing.T) {
	dir := interopDir(t)

	uuid := cryptox.MustParseUUID("b831381d-6324-4d53-ad4f-8cda48b30811")
	h := &requestHeader{
		Version:   instructionVersion,
		ResponseV: 0x5a,
		Option:    0,
		Padding:   3,
		Security:  SecurityChaCha20Poly1305,
		Command:   cmdTCP,
		Address:   "target.example:8443",
	}
	copy(h.BodyIV[:], bytesRange(16))
	copy(h.BodyKey[:], bytesRange2(16, 32))

	payload, err := h.encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	frame, err := sealRequestHeader(CmdKey(uuid), payload)
	if err != nil {
		t.Fatalf("sealRequestHeader: %v", err)
	}
	if err := os.WriteFile(dir+"/vmess_go_request.bin", frame, 0o600); err != nil {
		t.Fatalf("write go request: %v", err)
	}
}

func bytesRange(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func bytesRange2(from, to int) []byte {
	b := make([]byte, to-from)
	for i := range b {
		b[i] = byte(from + i)
	}
	return b
}

// TestInteropReadPythonResponse points the client-side response reader at a
// response blob produced by the Python implementation: header, then a chunked
// body that ends with the empty end-of-transmission packet.
func TestInteropReadPythonResponse(t *testing.T) {
	dir := interopDir(t)
	blob, err := os.ReadFile(dir + "/vmess_py_response.bin")
	if err != nil {
		t.Fatalf("read python response: %v", err)
	}

	// The Python emitter used request body IV 00..0f and key 10..1f, so the
	// response pair is derived from those fixed values.
	bodyIV := bytesRange(16)
	bodyKey := bytesRange2(16, 32)
	respKey, respIV := responseBodyKeys(bodyKey, bodyIV)

	conn := &sliceConn{data: blob}
	if err := readResponseHeader(conn, respKey, respIV, 0x5a); err != nil {
		t.Fatalf("readResponseHeader: %v", err)
	}

	aead, err := SecurityChaCha20Poly1305.bodyAEAD(respKey)
	if err != nil {
		t.Fatalf("bodyAEAD: %v", err)
	}
	body := newBodyConn(conn, aead, toIV(respIV))
	got, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(got) != "hello from python" {
		t.Fatalf("body = %q, want %q", got, "hello from python")
	}
}

// TestInteropEmitGoResponse writes a response header plus body so the Python
// implementation can parse them.
func TestInteropEmitGoResponse(t *testing.T) {
	dir := interopDir(t)

	bodyIV := bytesRange(16)
	bodyKey := bytesRange2(16, 32)
	respKey, respIV := responseBodyKeys(bodyKey, bodyIV)

	header, err := sealResponseHeader(respKey, respIV, 0x5a)
	if err != nil {
		t.Fatalf("sealResponseHeader: %v", err)
	}
	aead, err := SecurityChaCha20Poly1305.bodyAEAD(respKey)
	if err != nil {
		t.Fatalf("bodyAEAD: %v", err)
	}

	// A bytes.Buffer stands in for the connection: bodyConn only needs Write
	// and, for the end-of-transmission packet, an optional CloseWrite.
	var buf bytes.Buffer
	body := newBodyConn(&bufferConn{Buffer: &buf}, aead, toIV(respIV))
	if _, err := body.Write([]byte("hello from go")); err != nil {
		t.Fatalf("write body: %v", err)
	}
	if err := body.closeWrite(); err != nil {
		t.Fatalf("closeWrite: %v", err)
	}

	if err := os.WriteFile(dir+"/vmess_go_response.bin", append(header, buf.Bytes()...), 0o600); err != nil {
		t.Fatalf("write go response: %v", err)
	}
}

// bufferConn adapts a bytes.Buffer to the net.Conn surface bodyConn uses.
type bufferConn struct {
	*bytes.Buffer
}

func (b *bufferConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (b *bufferConn) Write(p []byte) (int, error)      { return b.Buffer.Write(p) }
func (b *bufferConn) Close() error                     { return nil }
func (b *bufferConn) LocalAddr() net.Addr              { return nil }
func (b *bufferConn) RemoteAddr() net.Addr             { return nil }
func (b *bufferConn) SetDeadline(time.Time) error      { return nil }
func (b *bufferConn) SetReadDeadline(time.Time) error  { return nil }
func (b *bufferConn) SetWriteDeadline(time.Time) error { return nil }
func (b *bufferConn) CloseWrite() error                { return nil }

// ensure the adapter still satisfies the interfaces the package expects.
var _ = context.Background
var _ = transport.CmdConnectTCP
var _ net.Conn = (*bufferConn)(nil)
var _ net.Conn = (*sliceConn)(nil)
