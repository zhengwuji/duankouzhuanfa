package transport

import "crypto/subtle"

// constantTimeEqual compares two strings without leaking their contents
// through timing.
func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
