package darwin

import (
	"bytes"
	"testing"

	"github.com/knight-byte/contraband/internal/event"
)

func FuzzParsePktap(f *testing.F) {
	f.Add([]byte("1.2 (proc curl:1, out) IP\n\t0x0000:  4500 0028\n"))
	f.Fuzz(func(t *testing.T, input []byte) {
		_ = parsePktap(bytes.NewReader(input), func(event.Event) bool { return true })
	})
}
