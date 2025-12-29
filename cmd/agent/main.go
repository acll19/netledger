package main

import (
	"time"

	"github.com/acll19/netledger/agent"
)

func main() {
	fi := 2 * time.Second
	node := "with-cillium-worker2"
	server := "http://localhost:8080"
	debug := true
	err := agent.Run(fi, node, server, debug)
	if err != nil {
		panic(err)
	}
}
