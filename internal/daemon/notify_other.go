//go:build !darwin

package daemon

import "context"

// desktopNotify is not implemented off macOS yet; alerts still reach the log
// and `contraband watch`.
func desktopNotify(context.Context, uint32, string, string) error { return nil }
