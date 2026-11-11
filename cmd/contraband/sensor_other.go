//go:build !linux && !darwin

package main

import (
	"errors"
	"log/slog"

	"github.com/knight-byte/contraband/internal/daemon"
)

func platformSensor(*slog.Logger) (daemon.Sensor, error) {
	return nil, errors.New("no network sensor for this platform yet; start the daemon with -replay")
}
