package main

import (
	"flag"
	"time"

	"github.com/acll19/netledger/internal/agent"
)

var (
	server      string
	serviceCidr string
	node        string
	debug       bool
)

func main() {
	flag.Parse()

	fi := 2 * time.Second
	err := agent.Run(fi, node, server, serviceCidr, debug)
	if err != nil {
		panic(err)
	}
}

func init() {
	flag.StringVar(&server, "server", "", "The classifier path to send flows to")
	flag.StringVar(&serviceCidr, "serviceCidr", "", "The cluster service CIDR")
	flag.StringVar(&node, "node", "", "Agent node name")
	flag.BoolVar(&debug, "debug", false, "Enable debug logging")
}
