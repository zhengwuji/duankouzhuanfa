package webui

import "encoding/json"

// jsonMarshal is the encoder the console uses for its own internal copies.
//
// It exists as a named function so the intent at every call site is "produce
// the canonical wire form of this value", which is what makes the redaction
// round-trip and the mutate clone agree on field names.
func jsonMarshal(v any) ([]byte, error) {
	return json.Marshal(v)
}
