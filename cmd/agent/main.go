package main

import (
	"time"

	"github.com/acll19/netledger/agent"
)

func main() {
	fi := 2 * time.Second
	node := "with-cillium-worker2"
	err := agent.Run(fi, node)
	if err != nil {
		panic(err)
	}
}
