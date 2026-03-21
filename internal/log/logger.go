package log

import (
	"log/slog"
	"os"
)

func SetupLogger(logLevel string) {
	var logLevelOpt slog.Level
	switch logLevel {
	case "debug":
		logLevelOpt = slog.LevelDebug
	case "info":
		logLevelOpt = slog.LevelInfo
	case "warn":
		logLevelOpt = slog.LevelWarn
	case "error":
		logLevelOpt = slog.LevelError
	default:
		logLevelOpt = slog.LevelInfo
	}

	dl := slog.New(
		slog.NewJSONHandler(
			os.Stdout,
			&slog.HandlerOptions{Level: logLevelOpt},
		),
	)
	slog.SetDefault(dl)
}
