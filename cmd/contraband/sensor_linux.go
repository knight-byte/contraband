package main

import (
	"log/slog"

	"github.com/knight-byte/contraband/internal/daemon"
	"github.com/knight-byte/contraband/internal/sensor/linux"
)

func platformSensor(logger *slog.Logger) (daemon.Sensor, error) {
	return linux.New(logger)
}
