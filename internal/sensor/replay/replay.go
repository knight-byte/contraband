package replay

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/knight-byte/contraband/internal/event"
)

// Sensor feeds recorded events from a JSON Lines file. It stands in for a
// platform sensor in tests and on hosts without one.
type Sensor struct {
	Path string
}

func (sensor Sensor) Track(uint32) error { return nil }

func (sensor Sensor) Run(ctx context.Context, events chan<- event.Event) error {
	file, err := os.Open(sensor.Path)
	if err != nil {
		return fmt.Errorf("replay: %w", err)
	}
	defer file.Close() //nolint:errcheck // read-only
	return Decode(ctx, file, events)
}

func Decode(ctx context.Context, reader io.Reader, events chan<- event.Event) error {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for line := 1; scanner.Scan(); line++ {
		if len(scanner.Bytes()) == 0 {
			continue
		}
		var evt event.Event
		if err := json.Unmarshal(scanner.Bytes(), &evt); err != nil {
			return fmt.Errorf("replay line %d: %w", line, err)
		}
		if evt.Time.IsZero() {
			evt.Time = time.Now()
		}
		select {
		case events <- evt:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("replay: %w", err)
	}
	return nil
}
