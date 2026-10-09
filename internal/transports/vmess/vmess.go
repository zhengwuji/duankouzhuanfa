// Package vmess implements the VMess protocol in its AEAD authentication form,
// which is the only form modern v2ray and Xray clients negotiate.
//
// # Why AEAD only
//
// VMess defines two header authentication modes. The legacy MD5 mode computes
// an HMAC-MD5 over a coarse timestamp and then encrypts the instruction section
// with AES-128-CFB, so the header carries no integrity protection at all: an
// observer can flip bits in a request without detection. v2ray deprecated the
// mode and Xray rejects it outright. This package implements AEAD only and
// rejects a legacy request as a protocol violation. That is a deliberate
// interoperability cut, not an oversight.
//
// # Request (client → relay)
//
//	offset  size  field
//	0       16    EAuID    AES-128 block encryption of Timestamp|Rand|CRC32
//	16      18    ALength  AES-128-GCM of the 2-byte instruction length (2+16)
//	34      8     Nonce    random, and a KDF path component for both AEADs
//	42      Y     AHeader  AES-128-GCM of the instruction section below
//	42+Y    …     Data     standard-format chunk stream
//
// ALength comes before Nonce on the wire even though its key derivation needs
// the nonce; the relay therefore buffers 18 bytes, then 8 bytes, then derives.
//
// # Instruction section (the AHeader plaintext)
//
//	offset  size  field
//	0       1     version (always 1)
//	1       16    request body IV
//	17      16    request body key
//	33      1     response authentication V
//	34      1     option bits
//	35      1     margin P (high nibble) | security (low nibble)
//	36      1     reserved (must be 0)
//	37      1     command (0x01 TCP, 0x02 UDP)
//	38      2     port, big endian
//	40      1     address type (0x01 IPv4, 0x02 domain, 0x03 IPv6)
//	41      N     address
//	41+N    P     random padding
//	…       4     FNV-1a 32 of every preceding byte, big endian
//
// Margin and security share one byte, so the padding length is limited to 15.
// v2ray rolls it from 0..15 for exactly this reason. The checksum is not a MAC;
// it exists so a relay can reject a mangled header before doing any real work,
// and integrity actually comes from the AES-GCM tag over the whole section.
//
// # Data section
//
// Each direction is an independent chunk stream:
//
//	2 bytes   length L, big endian, of the encrypted packet
//	L bytes   the AEAD ciphertext (plaintext plus a 16-byte tag)
//
// The AEAD nonce is the 2-byte big-endian packet counter followed by the first
// ten bytes of that direction's IV. The counter starts at 0 and increments once
// per packet. An empty packet, that is L equal to the tag size, terminates the
// direction; this package emits it from CloseWrite so a half-close reaches the
// peer as a clean end of transmission.
//
// This build always sets the option byte to 0, which means: chunk stream off
// (the length field is the literal length, never XORed with a SHAKE128 mask),
// no global padding, no authenticated length, no TCP-connection reuse. Chunking
// is therefore the only framing layer, and every byte is covered by AEAD tags.
//
// # Response (relay → client)
//
//	offset  size  field
//	0       18    AES-128-GCM of the 2-byte response header length
//	18      M+16  AES-128-GCM of the response header content
//	…             response data, chunked as above
//
// The response header content is
//
//	1 byte  response authentication V, echoing the client's value
//	1 byte  option (0x01 would mean "reuse the TCP connection")
//	1 byte  command (0x01 would be a dynamic-port instruction)
//	1 byte  command content length M
//	M bytes command content
//
// This build sends option 0, command 0 and M 0, and accepts nothing else: a
// dynamic-port response is rejected rather than half-handled.
//
// # Compatibility notes
//
//   - The response body key and IV are SHA-256 of the request body key and IV,
//     truncated to 16 bytes, which is what the specification and both reference
//     implementations use for AEAD sessions.
//   - Replay protection is the 120-second timestamp window on EAuID, matching
//     v2ray's AEAD validator. v2ray additionally keeps a per-user anti-replay
//     filter over seen EAuIDs; that is not implemented here, so a captured
//     request can be replayed inside the window. The relay treats VMess as a
//     credential-bearing transport, not as a replay-proof one.
//   - The option byte is always 0 on the wire, so chunk masking, global padding
//     and the authenticated-length experiment are unimplemented in both
//     directions. A peer that enables them is rejected.
//   - Security 0x01 (legacy AES-128-CFB), 0x06 (zero) and the MD5 handshake are
//     rejected.
//   - UDP associate is framed (command 0x02) but the relay reports it as
//     CmdUDPAssociate; whether UDP is carried is the relay's decision, not this
//     package's.
//
// The header and response framing above are cross-checked against an
// independent implementation of the same specification in
// interop_test.go, which is skipped unless VMESS_INTEROP_DIR is set.
package vmess

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"hash/fnv"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"porttransit/internal/cryptox"
	"porttransit/internal/logx"
	"porttransit/internal/transport"
)

// Name is the registry key.
const Name = "vmess"

// DefaultPort is the conventional listen port. VMess is normally wrapped in TLS
// or WebSocket, so 443 is what share links carry.
const DefaultPort = 443

func init() {
	transport.Register(transport.Factory{
		Name:         Name,
		Description:  "VMess AEAD, compatible with v2ray and Xray. Self-encrypting; the legacy MD5 handshake is not supported.",
		NativeHeader: true,
		DefaultPort:  DefaultPort,
		Build:        func() (transport.Dialer, transport.Handler) { return Dialer{}, Handler{} },
	})
}

// Settings keys understood by this transport.
const (
	// SettingUUID is the user identifier shared with the relay. VMess derives
	// every key it uses from it, so it is a credential, not a label.
	SettingUUID = "uuid"
	// SettingServerName overrides the SNI.
	SettingServerName = "serverName"
	// SettingInsecureSkipVerify accepts any server certificate.
	SettingInsecureSkipVerify = "insecure"
	// SettingTLS wraps the stream in TLS. Default true: bare VMess is
	// recognisable on the wire even though its payload is encrypted.
	SettingTLS = "tls"
	// SettingCertFile and SettingKeyFile give the relay its certificate.
	SettingCertFile = "certFile"
	SettingKeyFile  = "keyFile"
	// SettingTimeout bounds the handshake.
	SettingTimeout = "timeout"
	// SettingMinVersion pins the minimum TLS version.
	SettingMinVersion = "minVersion"
	// SettingSecurity selects the data-section cipher: "aes-128-gcm",
	// "chacha20-poly1305", "none", or "auto".
	SettingSecurity = "security"
	// SettingAlterID is accepted and ignored.
	//
	// VMess AEAD has no alterId: the field belonged to the legacy MD5 handshake,
	// where it multiplied the number of valid authentication ids so that a
	// client could rotate them. Share links and subscription formats still
	// carry "alterId": 0 for VMess, so accepting and ignoring the key lets an
	// imported profile load instead of failing on an unknown setting.
	SettingAlterID = "alterId"
)

// Security is the data-section cipher, encoded in the low nibble of the
// instruction section's security byte.
type Security byte

const (
	// SecurityLegacy is AES-128-CFB. Deprecated and rejected.
	SecurityLegacy Security = 0x01
	// SecurityAES128GCM is the fastest suite on CPUs with AES-NI.
	SecurityAES128GCM Security = 0x03
	// SecurityChaCha20Poly1305 is the fastest suite without AES-NI.
	SecurityChaCha20Poly1305 Security = 0x04
	// SecurityNone disables data-section encryption. The header is still AEAD
	// protected, so this is not "no authentication", only "no confidentiality".
	SecurityNone Security = 0x05
	// SecurityZero forces an unencrypted, unchunked raw stream and is rejected.
	SecurityZero Security = 0x06
)

// String renders the suite the way settings and logs spell it.
func (s Security) String() string {
	switch s {
	case SecurityLegacy:
		return "aes-128-cfb"
	case SecurityAES128GCM:
		return "aes-128-gcm"
	case SecurityChaCha20Poly1305:
		return "chacha20-poly1305"
	case SecurityNone:
		return "none"
	case SecurityZero:
		return "zero"
	default:
		return fmt.Sprintf("unknown(0x%02x)", byte(s))
	}
}

// ParseSecurity maps a settings value to a suite. "auto" and the empty string
// select the same default the rest of the tree uses for encrypted transports.
func ParseSecurity(name string) (Security, error) {
	switch name {
	case "", "auto":
		return SecurityChaCha20Poly1305, nil
	case "aes-128-gcm":
		return SecurityAES128GCM, nil
	case "chacha20-poly1305", "chacha20-ietf-poly1305":
		return SecurityChaCha20Poly1305, nil
	case "none":
		return SecurityNone, nil
	case "aes-128-cfb":
		return 0, fmt.Errorf("%w: vmess legacy AES-128-CFB data sections are not supported", transport.ErrProtocol)
	default:
		return 0, fmt.Errorf("%w: vmess unknown security %q", transport.ErrProtocol, name)
	}
}

// bodyAEAD builds the AEAD that protects one direction's chunk stream.
//
// ChaCha20-Poly1305 in VMess is not keyed by the 16-byte instruction key
// directly: the suite is defined over a 32-byte key built as MD5(key) followed
// by MD5(MD5(key)). That expansion is fixed by the protocol and is why the two
// suites are not interchangeable even though they share the nonce layout.
func (s Security) bodyAEAD(key []byte) (cipher.AEAD, error) {
	switch s {
	case SecurityAES128GCM:
		return cryptox.NewAEAD(cryptox.CipherAES128GCM, key)
	case SecurityChaCha20Poly1305:
		first := cryptox.MD5Sum(key)
		expanded := make([]byte, 0, 32)
		expanded = append(expanded, first...)
		expanded = append(expanded, cryptox.MD5Sum(first)...)
		return cryptox.NewAEAD(cryptox.CipherChaCha20Poly1305, expanded)
	case SecurityNone:
		return nil, nil
	default:
		return nil, fmt.Errorf("%w: vmess security 0x%02x is not supported", transport.ErrProtocol, byte(s))
	}
}

// Option bits in the instruction section. This build always sends zero and
// rejects any peer that sets one, so these exist to name the bits in the
// rejection message: an operator debugging a client that sets optChunkMask needs
// to be told which feature is missing, not just that the option byte was 0x04.
const (
	// optChunkStream enables the chunked data format.
	optChunkStream byte = 0x01
	// optReuseConn asks to reuse the TCP connection. Deprecated by v2ray.
	optReuseConn byte = 0x02
	// optChunkMask XORs the chunk length with a SHAKE128 mask derived from the
	// request body IV.
	optChunkMask byte = 0x04
	// optGlobalPadding appends SHAKE128-derived padding to every chunk.
	optGlobalPadding byte = 0x08
	// optAuthLength protects the chunk length with its own AEAD.
	optAuthLength byte = 0x10
)

// describeOptions names the set bits of an option byte.
func describeOptions(opt byte) string {
	names := []struct {
		bit  byte
		name string
	}{
		{optChunkStream, "chunk-stream"},
		{optReuseConn, "reuse-connection"},
		{optChunkMask, "chunk-masking"},
		{optGlobalPadding, "global-padding"},
		{optAuthLength, "authenticated-length"},
	}
	out := ""
	for _, n := range names {
		if opt&n.bit == 0 {
			continue
		}
		if out != "" {
			out += ", "
		}
		out += n.name
	}
	if out == "" {
		out = "reserved"
	}
	return out
}

// Instruction section constants.
const (
	// instructionVersion is the only version the protocol has ever defined.
	instructionVersion = 1
	// cmdTCP and cmdUDP are the command byte values.
	cmdTCP = 0x01
	cmdUDP = 0x02
	// Address type values. Note that VMess numbers them 1/2/3 like VLESS and
	// unlike SOCKS5, which uses 1/3/4.
	addrTypeIPv4   = 0x01
	addrTypeDomain = 0x02
	addrTypeIPv6   = 0x03
	// minInstructionLen is the size of an instruction section with a one-byte
	// address, no padding and the checksum.
	minInstructionLen = 1 + 16 + 16 + 1 + 1 + 1 + 1 + 1 + 2 + 1 + 4
	// maxPadding is the largest margin the shared nibble can express.
	maxPadding = 15
	// checksumLen is the FNV-1a trailer.
	checksumLen = 4
)

// Response header constants.
const (
	// responseHeaderMinLen covers V, option, command and command length.
	responseHeaderMinLen = 4
	// responseHeaderMaxLen bounds the buffering a hostile relay can force. The
	// reference implementation never exceeds four bytes here.
	responseHeaderMaxLen = 256
	// gcmTagLen is the AES-GCM tag length, appended to every ciphertext.
	gcmTagLen = 16
	// aeadLengthFieldLen is the 2-byte plaintext plus the tag.
	aeadLengthFieldLen = 2 + gcmTagLen
	// connectionNonceLen is the random value that also feeds both KDFs.
	connectionNonceLen = 8
	// eauidLen is the encrypted authentication id.
	eauidLen = 16
	// requestHeaderFixedLen is EAuID, ALength and Nonce.
	requestHeaderFixedLen = eauidLen + aeadLengthFieldLen + connectionNonceLen
)

// Chunk stream constants.
const (
	// maxChunkLength is the largest value the 2-byte length field may carry.
	// The specification caps it at 2^14.
	maxChunkLength = 1 << 14
	// maxSkew bounds how far the EAuID timestamp may differ from the relay
	// clock. It matches v2ray's AEAD validator.
	maxSkew = 120 * time.Second
)

// KDF path components. Every one of these strings is fixed by the protocol;
// changing a character changes every key.
const (
	// kdfRoot is the literal HMAC key of the innermost hash of the chain. It is
	// a constant, not a secret: the secret enters as the message of the last
	// level, so the chain itself can be public.
	kdfRoot = "VMess AEAD KDF"

	kdfSaltAuthID               = "AES Auth ID Encryption"
	kdfSaltHeaderLengthKey      = "VMess Header AEAD Key_Length"
	kdfSaltHeaderLengthIV       = "VMess Header AEAD Nonce_Length"
	kdfSaltHeaderKey            = "VMess Header AEAD Key"
	kdfSaltHeaderIV             = "VMess Header AEAD Nonce"
	kdfSaltResponseHeaderLenKey = "AEAD Resp Header Len Key"
	kdfSaltResponseHeaderLenIV  = "AEAD Resp Header Len IV"
	kdfSaltResponseHeaderKey    = "AEAD Resp Header Key"
	kdfSaltResponseHeaderIV     = "AEAD Resp Header IV"

	// cmdKeySuffix domain-separates the UUID from the key it derives. It is a
	// fixed literal from the protocol, not a secret.
	cmdKeySuffix = "c48619fe-8f02-49e0-b9e9-edf763e17e21"

	// sha256BlockSize is the block size of every hash in the KDF chain.
	sha256BlockSize = 64
	// hmacIPadByte and hmacOPadByte are the RFC 2104 pad bytes.
	hmacIPadByte byte = 0x36
	hmacOPadByte byte = 0x5c

	// chunkNoncePrefixLen is the per-packet counter that opens the chunk nonce.
	chunkNoncePrefixLen = 2
	// chunkNonceIVLen is how much of the direction IV the nonce carries.
	chunkNonceIVLen = 10
	// aeadNonceLen is the AES-GCM nonce size.
	aeadNonceLen = chunkNoncePrefixLen + chunkNonceIVLen
)

// KDF is the VMess key derivation function.
//
// It is not a single HMAC. The specification defines a chain:
//
//	hmac_creator = HMAC(SHA256, "VMess AEAD KDF")
//	for each path component p: hmac_creator = HMAC(hmac_creator, p)
//	return hmac_creator(key)
//
// Each component re-keys an HMAC whose underlying hash function is the previous
// level, so level i is
//
//	H_i(m) = H_{i-1}((p_i ⊕ opad) ‖ H_{i-1}((p_i ⊕ ipad) ‖ m))
//
// with H_0 = HMAC-SHA256 keyed by kdfRoot. Every level has SHA-256's block size
// and digest size, because an HMAC's BlockSize is its inner hash's block size
// and SHA-256's is 64 at every level.
//
// This implementation evaluates that recursion directly. The reference
// implementations instead build the same chain by passing a live hash.Hash as
// the "hash function" of the next HMAC, relying on the sharing of inner and
// outer state; the two are equivalent, and the test suite pins that equivalence
// against a literal transcription of the reference code.
func KDF(key []byte, path ...string) []byte {
	h := func(msg []byte) []byte { return cryptox.HMACSHA256([]byte(kdfRoot), msg) }
	for _, component := range path {
		prev := h
		k := []byte(component)
		h = func(msg []byte) []byte { return hmacWith(prev, k, msg) }
	}
	return h(key)
}

// KDF16 is KDF truncated to a 16-byte key, which is what every AES-128 key in
// VMess needs.
func KDF16(key []byte, path ...string) []byte {
	return KDF(key, path...)[:16]
}

// hmacWith computes HMAC over msg with prev standing in for the hash function.
//
// Keys longer than the block size are replaced by their own digest, per RFC
// 2104. No VMess path component is that long, so the branch only matters for
// callers that derive a key from a long label.
func hmacWith(prev func([]byte) []byte, key, msg []byte) []byte {
	k := make([]byte, sha256BlockSize)
	if len(key) > sha256BlockSize {
		copy(k, prev(key))
	} else {
		copy(k, key)
	}

	inner := make([]byte, 0, sha256BlockSize+len(msg))
	for _, b := range k {
		inner = append(inner, b^hmacIPadByte)
	}
	inner = append(inner, msg...)
	digest := prev(inner)

	outer := make([]byte, 0, sha256BlockSize+len(digest))
	for _, b := range k {
		outer = append(outer, b^hmacOPadByte)
	}
	outer = append(outer, digest...)
	return prev(outer)
}

// CmdKey derives the master key for a user.
//
// The UUID is not used directly: it is concatenated with a fixed literal and
// hashed with MD5. MD5 is used here because the protocol says so; it is a
// domain-separation step, not a security boundary, and the value it produces is
// only ever used as an AES-128 key or KDF input.
func CmdKey(uuid cryptox.UUID) []byte {
	buf := make([]byte, 0, 16+len(cmdKeySuffix))
	buf = append(buf, uuid[:]...)
	buf = append(buf, cmdKeySuffix...)
	return cryptox.MD5Sum(buf)
}

// createAuthID builds the EAuID: an AES-128 block encryption, in ECB mode over
// a single block, of Timestamp|Rand|CRC32.
//
// The block cipher is used without a mode on purpose. EAuID must be decryptable
// by a relay that holds only CmdKey and must not carry a random IV, so a single
// block with no chaining is the whole construction. The CRC over the first 12
// plaintext bytes is what lets a relay recognise its own users before spending
// a GCM open on the rest of the header, and the timestamp is what bounds
// replay.
func createAuthID(cmdKey []byte, unix int64) ([eauidLen]byte, error) {
	var out [eauidLen]byte
	plain := make([]byte, eauidLen)
	binary.BigEndian.PutUint64(plain[0:8], uint64(unix))
	copy(plain[8:12], cryptox.RandomBytes(4))
	binary.BigEndian.PutUint32(plain[12:16], crc32.ChecksumIEEE(plain[0:12]))

	blk, err := aes.NewCipher(KDF16(cmdKey, kdfSaltAuthID))
	if err != nil {
		return out, fmt.Errorf("vmess: auth id cipher: %w", err)
	}
	blk.Encrypt(out[:], plain)
	return out, nil
}

// openAuthID decrypts and validates an EAuID, returning the timestamp it
// carries.
//
// A CRC match is proof that the peer knows the UUID, because the block cipher
// key is derived from CmdKey: a peer that guessed wrong produces a plaintext
// whose CRC does not match. That is the whole authentication of a VMess
// request, so the check happens before any other work.
func openAuthID(cmdKey []byte, authID [eauidLen]byte) (time.Time, error) {
	blk, err := aes.NewCipher(KDF16(cmdKey, kdfSaltAuthID))
	if err != nil {
		return time.Time{}, fmt.Errorf("vmess: auth id cipher: %w", err)
	}
	plain := make([]byte, eauidLen)
	blk.Decrypt(plain, authID[:])

	want := binary.BigEndian.Uint32(plain[12:16])
	if crc32.ChecksumIEEE(plain[0:12]) != want {
		return time.Time{}, fmt.Errorf("%w: vmess auth id does not belong to this user", transport.ErrAuthFailed)
	}
	ts := int64(binary.BigEndian.Uint64(plain[0:8]))
	when := time.Unix(ts, 0)
	// Symmetric window: a client clock may run fast as well as slow.
	delta := time.Since(when)
	if delta < 0 {
		delta = -delta
	}
	if delta > maxSkew {
		return time.Time{}, fmt.Errorf("%w: vmess auth id timestamp is %s from the relay clock", transport.ErrAuthFailed, delta.Truncate(time.Second))
	}
	return when, nil
}

// requestHeader is the decoded instruction section.
type requestHeader struct {
	Version   byte
	BodyIV    [16]byte
	BodyKey   [16]byte
	ResponseV byte
	Option    byte
	Padding   byte
	Security  Security
	Command   byte
	Port      uint16
	Address   string
}

// encode renders the instruction section.
//
// The margin is drawn from 0..15 because it shares a byte with the security
// nibble, and the checksum covers everything before it, including the padding.
func (h *requestHeader) encode() ([]byte, error) {
	host, portStr, err := transport.SplitHostPort(h.Address)
	if err != nil {
		return nil, err
	}
	port, err := parsePort(portStr)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 0, 64)
	buf = append(buf, h.Version)
	buf = append(buf, h.BodyIV[:]...)
	buf = append(buf, h.BodyKey[:]...)
	buf = append(buf, h.ResponseV)
	buf = append(buf, h.Option)
	buf = append(buf, h.Padding<<4|byte(h.Security))
	buf = append(buf, 0) // reserved, must be 0
	buf = append(buf, h.Command)
	buf = binary.BigEndian.AppendUint16(buf, port)

	// VMess uses its own address type numbering: 1 IPv4, 2 domain, 3 IPv6.
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			buf = append(buf, addrTypeIPv4)
			buf = append(buf, v4...)
		} else {
			buf = append(buf, addrTypeIPv6)
			buf = append(buf, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, fmt.Errorf("%w: vmess domain %q is longer than 255 bytes", transport.ErrBadAddress, host)
		}
		buf = append(buf, addrTypeDomain, byte(len(host)))
		buf = append(buf, host...)
	}

	if h.Padding > 0 {
		buf = append(buf, cryptox.RandomBytes(int(h.Padding))...)
	}
	return binary.BigEndian.AppendUint32(buf, fnv1a32(buf)), nil
}

// decode parses and validates an instruction section.
//
// It deliberately refuses any reserved or option bit it does not implement
// rather than ignoring them: silently dropping chunk masking or global padding
// would desynchronise the chunk stream and turn a configuration error into a
// corrupted tunnel.
func decodeRequestHeader(b []byte) (*requestHeader, error) {
	if len(b) < minInstructionLen {
		return nil, fmt.Errorf("%w: vmess instruction section is %d bytes, need at least %d", transport.ErrProtocol, len(b), minInstructionLen)
	}
	body := b[:len(b)-checksumLen]
	if got, want := fnv1a32(body), binary.BigEndian.Uint32(b[len(b)-checksumLen:]); got != want {
		return nil, fmt.Errorf("%w: vmess instruction checksum mismatch", transport.ErrProtocol)
	}

	h := &requestHeader{}
	i := 0
	h.Version = body[i]
	i++
	copy(h.BodyIV[:], body[i:i+16])
	i += 16
	copy(h.BodyKey[:], body[i:i+16])
	i += 16
	h.ResponseV = body[i]
	i++
	h.Option = body[i]
	i++
	h.Padding = body[i] >> 4
	h.Security = Security(body[i] & 0x0f)
	i++
	if body[i] != 0 {
		return nil, fmt.Errorf("%w: vmess reserved instruction byte is 0x%02x", transport.ErrProtocol, body[i])
	}
	i++
	h.Command = body[i]
	i++
	h.Port = binary.BigEndian.Uint16(body[i : i+2])
	i += 2

	atyp := body[i]
	i++
	switch atyp {
	case addrTypeIPv4:
		if i+4 > len(body) {
			return nil, fmt.Errorf("%w: vmess truncated IPv4 address", transport.ErrProtocol)
		}
		h.Address = net.JoinHostPort(net.IP(body[i:i+4]).String(), fmt.Sprint(h.Port))
		i += 4
	case addrTypeIPv6:
		if i+16 > len(body) {
			return nil, fmt.Errorf("%w: vmess truncated IPv6 address", transport.ErrProtocol)
		}
		h.Address = net.JoinHostPort(net.IP(body[i:i+16]).String(), fmt.Sprint(h.Port))
		i += 16
	case addrTypeDomain:
		if i >= len(body) {
			return nil, fmt.Errorf("%w: vmess truncated domain length", transport.ErrProtocol)
		}
		n := int(body[i])
		i++
		if n == 0 {
			return nil, fmt.Errorf("%w: vmess zero-length domain", transport.ErrProtocol)
		}
		if i+n > len(body) {
			return nil, fmt.Errorf("%w: vmess truncated domain", transport.ErrProtocol)
		}
		h.Address = net.JoinHostPort(string(body[i:i+n]), fmt.Sprint(h.Port))
		i += n
	default:
		return nil, fmt.Errorf("%w: vmess address type 0x%02x", transport.ErrProtocol, atyp)
	}

	if i+int(h.Padding) != len(body) {
		return nil, fmt.Errorf("%w: vmess instruction section has %d trailing bytes", transport.ErrProtocol, len(body)-i-int(h.Padding))
	}
	return h, nil
}

// sealRequestHeader wraps an instruction section in the AEAD request header.
//
// Order matters: the length AEAD and the header AEAD are both keyed and nonced
// from the same EAuID and connection nonce, so the two KDF paths differ only in
// their fixed labels. The EAuID is also the additional authenticated data of
// both, which binds the ciphertexts to the identity the relay authenticated.
func sealRequestHeader(cmdKey, payload []byte) ([]byte, error) {
	authID, err := createAuthID(cmdKey, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	nonce := cryptox.RandomBytes(connectionNonceLen)

	authIDPath := string(authID[:])
	noncePath := string(nonce)

	lengthKey := KDF16(cmdKey, kdfSaltHeaderLengthKey, authIDPath, noncePath)
	lengthNonce := KDF(cmdKey, kdfSaltHeaderLengthIV, authIDPath, noncePath)[:aeadNonceLen]
	encryptedLength, err := sealAEAD(lengthKey, lengthNonce, authID[:], be16(uint16(len(payload))))
	if err != nil {
		return nil, err
	}

	headerKey := KDF16(cmdKey, kdfSaltHeaderKey, authIDPath, noncePath)
	headerNonce := KDF(cmdKey, kdfSaltHeaderIV, authIDPath, noncePath)[:aeadNonceLen]
	encryptedHeader, err := sealAEAD(headerKey, headerNonce, authID[:], payload)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, requestHeaderFixedLen+len(encryptedHeader))
	out = append(out, authID[:]...)
	out = append(out, encryptedLength...)
	out = append(out, nonce...)
	out = append(out, encryptedHeader...)
	return out, nil
}

// readRequestHeader reads and opens a full AEAD request header from r.
//
// The returned header also carries the raw request body IV and key, which the
// caller needs to build the two chunk streams.
func readRequestHeader(r io.Reader, cmdKey []byte) (*requestHeader, error) {
	var authID [eauidLen]byte
	if _, err := io.ReadFull(r, authID[:]); err != nil {
		return nil, err
	}
	if _, err := openAuthID(cmdKey, authID); err != nil {
		return nil, err
	}

	var encryptedLength [aeadLengthFieldLen]byte
	if _, err := io.ReadFull(r, encryptedLength[:]); err != nil {
		return nil, err
	}
	nonce := make([]byte, connectionNonceLen)
	if _, err := io.ReadFull(r, nonce); err != nil {
		return nil, err
	}

	authIDPath := string(authID[:])
	noncePath := string(nonce)

	lengthKey := KDF16(cmdKey, kdfSaltHeaderLengthKey, authIDPath, noncePath)
	lengthNonce := KDF(cmdKey, kdfSaltHeaderLengthIV, authIDPath, noncePath)[:aeadNonceLen]
	lengthPlain, err := openAEAD(lengthKey, lengthNonce, authID[:], encryptedLength[:])
	if err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(lengthPlain))
	if length == 0 || length > maxChunkLength {
		return nil, fmt.Errorf("%w: vmess instruction length %d is out of range", transport.ErrProtocol, length)
	}

	encryptedHeader := make([]byte, length+gcmTagLen)
	if _, err := io.ReadFull(r, encryptedHeader); err != nil {
		return nil, err
	}
	headerKey := KDF16(cmdKey, kdfSaltHeaderKey, authIDPath, noncePath)
	headerNonce := KDF(cmdKey, kdfSaltHeaderIV, authIDPath, noncePath)[:aeadNonceLen]
	payload, err := openAEAD(headerKey, headerNonce, authID[:], encryptedHeader)
	if err != nil {
		return nil, err
	}
	return decodeRequestHeader(payload)
}

// responseBodyKeys derives the response key and IV from the request pair.
//
// The specification truncates SHA-256 to 16 bytes. The full digest would be
// stronger, but a relay that sent 32-byte keys would simply not interoperate.
func responseBodyKeys(bodyKey, bodyIV []byte) (key, iv []byte) {
	return cryptox.SHA256Sum(bodyKey)[:16], cryptox.SHA256Sum(bodyIV)[:16]
}

// sealResponseHeader builds the relay's response header.
//
// The content is always {responseV, 0, 0, 0}: option 0 means "do not reuse the
// TCP connection", command 0 means "no dynamic-port instruction", and the
// command length is 0 because there is no command content. A client that sent
// response authentication V expects to read the same byte back, and it is the
// only value in this frame an attacker cannot predict, so it is worth echoing.
func sealResponseHeader(responseKey, responseIV []byte, responseV byte) ([]byte, error) {
	content := []byte{responseV, 0x00, 0x00, 0x00}

	lengthKey := KDF16(responseKey, kdfSaltResponseHeaderLenKey)
	lengthNonce := KDF(responseIV, kdfSaltResponseHeaderLenIV)[:aeadNonceLen]
	encryptedLength, err := sealAEAD(lengthKey, lengthNonce, nil, be16(uint16(len(content))))
	if err != nil {
		return nil, err
	}

	key := KDF16(responseKey, kdfSaltResponseHeaderKey)
	nonce := KDF(responseIV, kdfSaltResponseHeaderIV)[:aeadNonceLen]
	encryptedContent, err := sealAEAD(key, nonce, nil, content)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, len(encryptedLength)+len(encryptedContent))
	out = append(out, encryptedLength...)
	out = append(out, encryptedContent...)
	return out, nil
}

// readResponseHeader consumes and validates the relay's response header.
//
// A mismatch on the echoed authentication byte is fatal: it means the peer
// answered a request this client did not make, which is the only check VMess
// offers against a relay being swapped underneath a client.
func readResponseHeader(r io.Reader, responseKey, responseIV []byte, wantV byte) error {
	lengthKey := KDF16(responseKey, kdfSaltResponseHeaderLenKey)
	lengthNonce := KDF(responseIV, kdfSaltResponseHeaderLenIV)[:aeadNonceLen]
	var encryptedLength [aeadLengthFieldLen]byte
	if _, err := io.ReadFull(r, encryptedLength[:]); err != nil {
		return fmt.Errorf("vmess: read response header length: %w", err)
	}
	lengthPlain, err := openAEAD(lengthKey, lengthNonce, nil, encryptedLength[:])
	if err != nil {
		return err
	}
	length := int(binary.BigEndian.Uint16(lengthPlain))
	if length < responseHeaderMinLen || length > responseHeaderMaxLen {
		return fmt.Errorf("%w: vmess response header length %d is out of range", transport.ErrProtocol, length)
	}

	encryptedContent := make([]byte, length+gcmTagLen)
	if _, err := io.ReadFull(r, encryptedContent); err != nil {
		return fmt.Errorf("vmess: read response header: %w", err)
	}
	key := KDF16(responseKey, kdfSaltResponseHeaderKey)
	nonce := KDF(responseIV, kdfSaltResponseHeaderIV)[:aeadNonceLen]
	content, err := openAEAD(key, nonce, nil, encryptedContent)
	if err != nil {
		return err
	}
	if content[0] != wantV {
		return fmt.Errorf("%w: vmess response authentication byte mismatch", transport.ErrAuthFailed)
	}
	if content[2] != 0 {
		return fmt.Errorf("%w: vmess dynamic-port response is not supported", transport.ErrProtocol)
	}
	return nil
}

// bodyConn frames a byte stream into VMess data-section chunks.
//
// Reads and writes share the connection but never the counter: the request and
// response directions have their own key, IV and packet counter, which is why
// one bodyConn is created per direction.
type bodyConn struct {
	conn net.Conn
	aead cipher.AEAD
	iv   [16]byte

	readCount  uint16
	writeCount uint16

	readBuf []byte
	readErr error

	writeMu sync.Mutex
}

// newBodyConn builds a chunk stream. A nil AEAD means the "none" security,
// where chunks are still length-prefixed but not encrypted.
func newBodyConn(conn net.Conn, aead cipher.AEAD, iv [16]byte) *bodyConn {
	return &bodyConn{conn: conn, aead: aead, iv: iv}
}

// overhead is how many bytes the AEAD adds to every packet.
func (b *bodyConn) overhead() int {
	if b.aead == nil {
		return 0
	}
	return b.aead.Overhead()
}

// chunkNonce builds the per-packet nonce: a 2-byte counter then the first ten
// bytes of the direction's IV.
//
// The IV contributes only ten bytes, so two directions that reused an IV would
// still collide after 65536 packets. The protocol relies on the IV being random
// per connection, which is why it is generated fresh for every request.
func (b *bodyConn) chunkNonce(count uint16) []byte {
	nonce := make([]byte, aeadNonceLen)
	binary.BigEndian.PutUint16(nonce[:chunkNoncePrefixLen], count)
	copy(nonce[chunkNoncePrefixLen:], b.iv[:chunkNonceIVLen])
	return nonce
}

// Read returns the next plaintext bytes of the chunk stream.
func (b *bodyConn) Read(p []byte) (int, error) {
	if len(b.readBuf) == 0 {
		if b.readErr != nil {
			return 0, b.readErr
		}
		if err := b.readChunk(); err != nil {
			b.readErr = err
			return 0, err
		}
	}
	n := copy(p, b.readBuf)
	b.readBuf = b.readBuf[n:]
	return n, nil
}

// readChunk reads and opens one data packet.
func (b *bodyConn) readChunk() error {
	var lengthBuf [2]byte
	if _, err := io.ReadFull(b.conn, lengthBuf[:]); err != nil {
		return err
	}
	size := int(binary.BigEndian.Uint16(lengthBuf[:]))
	if size > maxChunkLength {
		return fmt.Errorf("%w: vmess chunk length %d exceeds %d", transport.ErrProtocol, size, maxChunkLength)
	}

	if b.aead == nil {
		if size == 0 {
			return io.EOF
		}
		plain := make([]byte, size)
		if _, err := io.ReadFull(b.conn, plain); err != nil {
			return err
		}
		b.readBuf = plain
		return nil
	}

	if size < b.aead.Overhead() {
		return fmt.Errorf("%w: vmess chunk length %d is smaller than the AEAD tag", transport.ErrProtocol, size)
	}
	ciphertext := make([]byte, size)
	if _, err := io.ReadFull(b.conn, ciphertext); err != nil {
		return err
	}
	nonce := b.chunkNonce(b.readCount)
	b.readCount++
	plain, err := b.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("%w: vmess data packet authentication failed", transport.ErrAuthFailed)
	}
	// A packet whose plaintext is empty is the end-of-transmission marker. The
	// tag was still verified above, so a forged terminator cannot truncate a
	// stream undetected.
	if len(plain) == 0 {
		return io.EOF
	}
	b.readBuf = plain
	return nil
}

// Write splits p into data packets and writes them.
func (b *bodyConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	b.writeMu.Lock()
	defer b.writeMu.Unlock()

	// The length field counts ciphertext, so the largest plaintext packet is
	// the protocol cap minus the tag.
	capacity := maxChunkLength - b.overhead()
	written := 0
	for written < len(p) {
		n := len(p) - written
		if n > capacity {
			n = capacity
		}
		chunk := p[written : written+n]
		var ciphertext []byte
		if b.aead == nil {
			ciphertext = chunk
		} else {
			nonce := b.chunkNonce(b.writeCount)
			b.writeCount++
			ciphertext = b.aead.Seal(nil, nonce, chunk, nil)
		}
		frame := make([]byte, 0, 2+len(ciphertext))
		frame = append(frame, be16(uint16(len(ciphertext)))...)
		frame = append(frame, ciphertext...)
		if _, err := b.conn.Write(frame); err != nil {
			return written, err
		}
		written += n
	}
	return written, nil
}

// closeWrite sends the empty end-of-transmission packet and half-closes the
// connection when the transport underneath supports it.
//
// Without the empty packet a peer that is reading the chunk stream would block
// forever on a clean shutdown, because TCP's EOF never reaches it through the
// framing layer.
func (b *bodyConn) closeWrite() error {
	b.writeMu.Lock()
	defer b.writeMu.Unlock()

	var frame []byte
	if b.aead == nil {
		frame = []byte{0x00, 0x00}
	} else {
		nonce := b.chunkNonce(b.writeCount)
		b.writeCount++
		ciphertext := b.aead.Seal(nil, nonce, nil, nil)
		frame = append(be16(uint16(len(ciphertext))), ciphertext...)
	}
	if _, err := b.conn.Write(frame); err != nil {
		return err
	}
	if cw, ok := b.conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// tunnelStream is the shared Stream implementation for both directions.
type tunnelStream struct {
	transport.Stream
	readBody  *bodyConn
	writeBody *bodyConn
}

// Read returns decrypted bytes from the peer.
func (t *tunnelStream) Read(p []byte) (int, error) { return t.readBody.Read(p) }

// Write encrypts p into data packets.
func (t *tunnelStream) Write(p []byte) (int, error) { return t.writeBody.Write(p) }

// CloseWrite ends this direction's chunk stream cleanly.
func (t *tunnelStream) CloseWrite() error { return t.writeBody.closeWrite() }

// clientStream is the client end of a VMess tunnel.
//
// It differs from the relay end only in that the relay's response header must be
// consumed before any response payload can be read. Reading it eagerly in
// dialOver, as v2ray's client does, means every caller sees a plain byte stream
// and never has to know that VMess prefixes the downlink with a header. The
// cost is one round trip during Dial, which the handshake budget already covers.
type clientStream struct {
	*tunnelStream
}

// Dialer establishes client→relay VMess streams.
type Dialer struct{}

// Name returns the registry key.
func (Dialer) Name() string { return Name }

// Dial performs the TLS handshake when enabled, writes the AEAD request header
// and returns a stream whose writes are chunked request data.
func (d Dialer) Dial(ctx context.Context, req transport.DialRequest) (transport.Stream, error) {
	timeout := req.Settings.GetDuration(SettingTimeout, 10*time.Second)
	if req.Timeout > 0 {
		timeout = req.Timeout
	}

	host, _, err := transport.SplitHostPort(req.ServerAddr)
	if err != nil {
		return nil, err
	}
	sni := req.ServerName
	if sni == "" {
		sni = req.Settings.GetString(SettingServerName, host)
	}

	raw, err := (&net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}).DialContext(ctx, "tcp", req.ServerAddr)
	if err != nil {
		return nil, err
	}
	if err := raw.SetDeadline(time.Now().Add(timeout)); err != nil {
		raw.Close()
		return nil, err
	}

	var conn net.Conn = raw
	if req.Settings.GetBool(SettingTLS, true) {
		tc := tls.Client(raw, &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: req.Settings.GetBool(SettingInsecureSkipVerify, true),
			MinVersion:         minVersion(req.Settings.GetString(SettingMinVersion, "1.2")),
			NextProtos:         []string{"h2", "http/1.1"},
		})
		if err := tc.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, fmt.Errorf("vmess: TLS handshake with %s: %w", req.ServerAddr, err)
		}
		conn = tc
	}
	return d.dialOver(ctx, conn, req)
}

// dialOver runs the VMess handshake over an already-established connection.
//
// It is separate from Dial so the wire format can be exercised against an
// in-memory pipe in tests, and so a future caller that has already obtained an
// obfuscated connection (WebSocket, REALITY, ...) can reuse the same path.
func (d Dialer) dialOver(ctx context.Context, conn net.Conn, req transport.DialRequest) (transport.Stream, error) {
	uuidStr := req.Settings.GetString(SettingUUID, "")
	if uuidStr == "" {
		conn.Close()
		return nil, fmt.Errorf("vmess: %s is required", SettingUUID)
	}
	uuid, err := cryptox.ParseUUID(uuidStr)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("vmess: %w", err)
	}
	security, err := ParseSecurity(req.Settings.GetString(SettingSecurity, "auto"))
	if err != nil {
		conn.Close()
		return nil, err
	}

	command := byte(cmdTCP)
	streamReq := req.Request
	if streamReq != nil && streamReq.Command == transport.CmdUDPAssociate {
		command = cmdUDP
	}
	if streamReq == nil || streamReq.Command == transport.CmdPing {
		// VMess has no ping command. As in the other native-header transports,
		// the probe is a TCP connect to the relay's own listening address: the
		// relay accepts it, answers the response header and closes, which still
		// exercises the whole handshake path and measures the real round trip.
		command = cmdTCP
		streamReq = &transport.Request{
			Command:   transport.CmdConnectTCP,
			Target:    req.ServerAddr,
			Transport: Name,
			Meta:      map[string]string{"ping": "true"},
		}
	}
	target := streamReq.Target

	header := &requestHeader{
		Version:   instructionVersion,
		ResponseV: cryptox.RandomBytes(1)[0],
		// Option 0: chunked framing only, no masking, no padding, no
		// authenticated length. Every byte still travels inside an AEAD tag.
		Option:   0x00,
		Padding:  cryptox.RandomBytes(1)[0] % (maxPadding + 1),
		Security: security,
		Command:  command,
		Address:  target,
	}
	copy(header.BodyIV[:], cryptox.RandomBytes(16))
	copy(header.BodyKey[:], cryptox.RandomBytes(16))

	payload, err := header.encode()
	if err != nil {
		conn.Close()
		return nil, err
	}
	frame, err := sealRequestHeader(CmdKey(uuid), payload)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if _, err := conn.Write(frame); err != nil {
		conn.Close()
		return nil, fmt.Errorf("vmess: write request header: %w", err)
	}

	requestAEAD, err := security.bodyAEAD(header.BodyKey[:])
	if err != nil {
		conn.Close()
		return nil, err
	}
	respKey, respIV := responseBodyKeys(header.BodyKey[:], header.BodyIV[:])
	responseAEAD, err := security.bodyAEAD(respKey)
	if err != nil {
		conn.Close()
		return nil, err
	}

	// The relay answers with its response header before any payload. Consuming
	// it here keeps the downlink aligned, so Read on the returned stream sees
	// only target data.
	if err := readResponseHeader(conn, respKey, respIV, header.ResponseV); err != nil {
		conn.Close()
		return nil, err
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, err
	}

	base := transport.NewStream(conn, streamReq, Name, 0)
	return &clientStream{tunnelStream: &tunnelStream{
		Stream:    base,
		readBody:  newBodyConn(conn, responseAEAD, toIV(respIV)),
		writeBody: newBodyConn(conn, requestAEAD, header.BodyIV),
	}}, nil
}

// Handler accepts relay-side VMess streams.
type Handler struct{}

// Name returns the registry key.
func (Handler) Name() string { return Name }

// Handle reads the AEAD request header from an accepted connection, answers
// with the response header and returns a stream carrying the decoded target.
func (h Handler) Handle(ctx context.Context, raw net.Conn, req transport.HandleRequest) (transport.Stream, error) {
	timeout := req.Settings.GetDuration(SettingTimeout, 10*time.Second)
	if req.Timeout > 0 {
		timeout = req.Timeout
	}

	uuidStr := req.Settings.GetString(SettingUUID, "")
	if uuidStr == "" {
		raw.Close()
		return nil, fmt.Errorf("vmess: %s is required", SettingUUID)
	}
	wantUUID, err := cryptox.ParseUUID(uuidStr)
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("vmess: %w", err)
	}

	var conn net.Conn = raw
	if req.Settings.GetBool(SettingTLS, true) {
		cert, err := loadCert(req.Settings)
		if err != nil {
			raw.Close()
			return nil, err
		}
		tc := tls.Server(raw, &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   minVersion(req.Settings.GetString(SettingMinVersion, "1.2")),
			NextProtos:   []string{"h2", "http/1.1"},
		})
		if err := raw.SetDeadline(time.Now().Add(timeout)); err != nil {
			raw.Close()
			return nil, err
		}
		if err := tc.HandshakeContext(ctx); err != nil {
			raw.Close()
			loggerFor(req.Logger).Debug("vmess: TLS handshake failed", "remote", transport.RemoteAddrString(raw), "err", err)
			return nil, err
		}
		conn = tc
	}

	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		conn.Close()
		return nil, err
	}

	cmdKey := CmdKey(wantUUID)
	header, err := readRequestHeader(conn, cmdKey)
	if err != nil {
		conn.Close()
		loggerFor(req.Logger).Debug("vmess: request rejected", "remote", transport.RemoteAddrString(raw), "err", err)
		return nil, err
	}
	if header.Version != instructionVersion {
		conn.Close()
		return nil, fmt.Errorf("%w: vmess version %d is not supported", transport.ErrProtocol, header.Version)
	}
	if header.Option != 0 {
		// Chunk masking, global padding and the authenticated-length
		// experiment all change the framing this relay implements; answering
		// anyway would desynchronise the stream.
		conn.Close()
		return nil, fmt.Errorf("%w: vmess option byte 0x%02x requests unsupported features (%s)", transport.ErrProtocol, header.Option, describeOptions(header.Option))
	}
	requestAEAD, err := header.Security.bodyAEAD(header.BodyKey[:])
	if err != nil {
		conn.Close()
		return nil, err
	}

	respKey, respIV := responseBodyKeys(header.BodyKey[:], header.BodyIV[:])
	responseAEAD, err := header.Security.bodyAEAD(respKey)
	if err != nil {
		conn.Close()
		return nil, err
	}
	responseHeader, err := sealResponseHeader(respKey, respIV, header.ResponseV)
	if err != nil {
		conn.Close()
		return nil, err
	}
	// The response header goes out before any payload so the client can start
	// reading without racing the target's first bytes.
	if _, err := conn.Write(responseHeader); err != nil {
		conn.Close()
		return nil, fmt.Errorf("vmess: write response header: %w", err)
	}

	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, err
	}

	streamReq := &transport.Request{
		Command:   transport.CmdConnectTCP,
		Target:    header.Address,
		Transport: Name,
		ClientID:  wantUUID.String(),
		Meta:      map[string]string{"security": header.Security.String()},
	}
	if header.Command == cmdUDP {
		streamReq.Command = transport.CmdUDPAssociate
	} else if header.Command != cmdTCP {
		conn.Close()
		return nil, fmt.Errorf("%w: vmess command 0x%02x is not supported", transport.ErrProtocol, header.Command)
	}

	base := transport.NewStream(conn, streamReq, Name, 0)
	return &tunnelStream{
		Stream:    base,
		readBody:  newBodyConn(conn, requestAEAD, header.BodyIV),
		writeBody: newBodyConn(conn, responseAEAD, toIV(respIV)),
	}, nil
}

// sealAEAD encrypts plaintext with a raw key and nonce.
func sealAEAD(key, nonce, additionalData, plaintext []byte) ([]byte, error) {
	aead, err := newRawAEAD(key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, additionalData), nil
}

// openAEAD decrypts ciphertext, mapping a tag failure onto ErrAuthFailed so
// callers can classify it without string matching.
func openAEAD(key, nonce, additionalData, ciphertext []byte) ([]byte, error) {
	aead, err := newRawAEAD(key)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, fmt.Errorf("%w: vmess header authentication failed", transport.ErrAuthFailed)
	}
	return plain, nil
}

// newRawAEAD builds an AES-128-GCM AEAD. Every header-level AEAD in VMess is
// AES-128-GCM regardless of the data-section security, because the header keys
// are always 16 bytes.
func newRawAEAD(key []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("vmess: header cipher: %w", err)
	}
	return cipher.NewGCM(blk)
}

// fnv1a32 is the checksum used by the instruction section.
func fnv1a32(b []byte) uint32 {
	h := fnv.New32a()
	_, _ = h.Write(b)
	return h.Sum32()
}

// be16 renders a big-endian uint16.
func be16(v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return b
}

// toIV widens a derived key or IV into the fixed array bodyConn expects.
func toIV(b []byte) [16]byte {
	var out [16]byte
	copy(out[:], b)
	return out
}

func parsePort(s string) (uint16, error) {
	var p int
	if _, err := fmt.Sscanf(s, "%d", &p); err != nil || p < 1 || p > 65535 {
		return 0, fmt.Errorf("%w: vmess bad port %q", transport.ErrBadAddress, s)
	}
	return uint16(p), nil
}

func loadCert(s transport.Settings) (tls.Certificate, error) {
	certFile := s.GetString(SettingCertFile, "")
	keyFile := s.GetString(SettingKeyFile, "")

	// When no explicit pair is configured, fall back to a pair kept beside the
	// data directory so a restart does not change the fingerprint.
	if certFile == "" && keyFile == "" {
		if dir := s.GetString("dataDir", ""); dir != "" {
			c := dir + "/certs/relay.crt"
			k := dir + "/certs/relay.key"
			if fileExists(c) && fileExists(k) {
				certFile, keyFile = c, k
			}
		}
	}

	return transport.LoadOrGenerateCertificate(certFile, keyFile, transport.SelfSignedOptions{
		CommonName: s.GetString("certCommonName", "porttransit-relay"),
		DNSNames:   s.GetStringSlice("certNames"),
	})
}

// fileExists reports whether p names an existing regular file.
func fileExists(p string) bool {
	if p == "" {
		return false
	}
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

func minVersion(s string) uint16 {
	switch s {
	case "1.3", "tls1.3", "TLS1.3":
		return tls.VersionTLS13
	default:
		return tls.VersionTLS12
	}
}

// loggerFor adapts the harness logger to the transport logger interface.
//
// A nil *logx.Logger is handed back as a typed nil rather than as an untyped
// nil interface. *logx.Logger's methods are written to tolerate a nil receiver,
// so a typed nil is safe to call; an untyped nil interface would panic on the
// first Debug, which is exactly the case a relay that runs without a logger
// hits.
// loggerFor adapts the shared logger to the transport package's minimal
// interface.
//
// It returns an explicit no-op rather than the nil pointer: a nil interface
// panics on the first method call, and the transports log from inside
// handshake paths where a panic would take down the whole relay.
func loggerFor(l *logx.Logger) transport.Logger {
	if l == nil {
		return transport.NopLogger()
	}
	return l
}
