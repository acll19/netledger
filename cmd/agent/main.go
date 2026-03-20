package main

import (
	"flag"
	"time"

	"github.com/acll19/netledger/internal/agent"
)

var (
	server string
	node   string
)

func main() {
	flag.Parse()

	fi := 1 * time.Second
	err := agent.Run(fi, node, server)
	if err != nil {
		panic(err)
	}
}

func init() {
	flag.StringVar(&server, "server", "", "The classifier path to send flows to")
	flag.StringVar(&node, "node", "", "Agent node name")
}
