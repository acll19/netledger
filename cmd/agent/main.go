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
	server   string
	node     string
	logLevel string
)

func main() {
	flag.Parse()
	log.SetupLogger(logLevel)

	fi := 5 * time.Second // TODO: consider making this configurable
	startupTime := time.Now().Unix()
	agent := agent.NewAgent(node, server, startupTime, fi)
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
}
