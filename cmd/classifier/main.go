// TODO
// agent will send pod namespace and name
// if pod not found assign "unknown"
// should keep map of active pod (pod IP to pod metadata)
// when informed that pod was deleted, move to tombstone cache for 120 seconds...
// ...before deleting for good
package main

import (
	"log"

	"github.com/acll19/netledger/internal/classifier/server"
	k8s "github.com/acll19/netledger/internal/kubernetes"
	"github.com/prometheus/client_golang/prometheus"
)

func main() {
	clientset, err := k8s.GetKubernetesClient()
	if err != nil {
		log.Fatalf("Error creating kubernetes client: %v", err)
	}

	server := server.NewServer(clientset)

	// Start watching Pods and Nodes
	go server.WatchPods()
	go server.WatchNodes()

	reg := prometheus.NewRegistry()
	reg.MustRegister(server)
	server.Start(reg)
}
