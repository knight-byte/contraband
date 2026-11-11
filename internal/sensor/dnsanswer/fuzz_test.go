package dnsanswer_test

import (
	"testing"
	"time"

	"github.com/knight-byte/contraband/internal/sensor/dnsanswer"
)

func FuzzParse(f *testing.F) {
	f.Add([]byte{0x21, 0x0f, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, payload []byte) {
		dnsanswer.Parse(time.Time{}, payload)
	})
}
