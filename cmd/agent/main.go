package main

import (
	"flag"
	"log/slog"
	"os"
	"time"

	"github.com/acll19/netledger/internal/agent"
)

var (
	server   string
	node     string
	logLevel string
)

func main() {
	flag.Parse()
	setupLogger(logLevel)

	fi := 1 * time.Second
	err := agent.Run(fi, node, server)
	if err != nil {
		panic(err)
	}
}

func setupLogger(logLevel string) {
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

func init() {
	flag.StringVar(&server, "server", "", "The classifier path to send flows to")
	flag.StringVar(&node, "node", "", "Agent node name")
	flag.StringVar(&logLevel, "log-level", "info", "Log level (debug, info, warn, error)")
}
