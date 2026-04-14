package main

import (
	"flag"
	"log/slog"
	"os"
	"time"

	"github.com/acll19/netledger/internal/agent"
	"github.com/acll19/netledger/internal/log"
)

var (
	server       string
	node         string
	logLevel     string
	pollInterval string
)

func main() {
	flag.Parse()
	log.SetupLogger(logLevel)

	pi := 5 * time.Second
	if pollInterval != "" {
		var err error
		pi, err = time.ParseDuration(pollInterval)
		if err != nil {
			slog.Warn("invalid poll-internal provided, using default 5s instead", "invalid value", pollInterval, "error", err)
		}
	}
	startupTime := time.Now().Unix()
	agent := agent.NewAgent(node, server, startupTime, pi)
	objs, links, err := agent.LoadEBPF()
	if err != nil {
		slog.Error("Error loading eBPF programs", "error", err)
		os.Exit(1)
	}

	defer func() {
		objs.Close()
		for _, link := range links {
			if err := link.Close(); err != nil {
				slog.Error("error closing link object", "message", err.Error())
			}
		}
	}()

	err = agent.Start()
	if err != nil {
		slog.Error("Error starting agent", "error", err)
		os.Exit(1)
	}
}

func init() {
	flag.StringVar(&server, "server", "", "The classifier path to send flows to")
	flag.StringVar(&node, "node", "", "Agent node name")
	flag.StringVar(&logLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	flag.StringVar(&pollInterval, "poll-interval", "5s", "How frequently the connection stats will be polled from the kernel. Defaults to 5s. Values must be in Go's time.Duration format.")
}
