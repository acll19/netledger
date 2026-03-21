package main

import (
	"flag"
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

	fi := 1 * time.Second
	startupTime := time.Now().Unix()
	err := agent.Run(fi, node, server, startupTime)
	if err != nil {
		panic(err)
	}
}

func init() {
	flag.StringVar(&server, "server", "", "The classifier path to send flows to")
	flag.StringVar(&node, "node", "", "Agent node name")
	flag.StringVar(&logLevel, "log-level", "info", "Log level (debug, info, warn, error)")
}
