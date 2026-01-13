package main

import (
	"os"
	"time"

	"github.com/acll19/netledger/internal/agent"
)

func main() {
	fi := 2 * time.Second
	node := os.Getenv("NODE_NAME")
	server := "http://172.18.0.1:8080/write-network-statistics"
	serviceCidr := "10.11.0.0/16"
	debug := true
	err := agent.Run(fi, node, server, serviceCidr, debug)
	if err != nil {
		panic(err)
	}
}
