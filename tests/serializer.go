package tests

import (
	"github.com/kabuke/fix-forside-libsignal-protocol-go/serialize"
)

// newSerializer will return a JSON serializer for testing.
func newSerializer() *serialize.Serializer {
	serializer := serialize.NewJSONSerializer()

	return serializer
}
