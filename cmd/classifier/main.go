// TODO
// agent will send pod namespace and name
// if pod not found assign "unknown"
// should keep map of active pod (pod IP to pod metadata)
// when informed that pod was deleted, move to tombstone cache for 120 seconds...
// ...before deleting for good
// should classify traffic
// should emit Prometheus metric
package main

import (
	"log"

	"github.com/acll19/netledger/internal/classifier/server"
	"github.com/acll19/netledger/internal/classifier/statistics"
	k8s "github.com/acll19/netledger/internal/kubernetes"
	"github.com/prometheus/client_golang/prometheus"
)

func main() {
	clientset, err := k8s.GetKubernetesClient()
	if err != nil {
		log.Fatalf("Error creating kubernetes client: %v", err)
	}

	server := &server.Server{
		Clientset:     clientset,
		PodIpIndex:    map[uint32]statistics.PodKey{},
		NodeIpIndex:   map[uint32]string{},
		PodIndex:      map[statistics.PodKey]server.PodInfo{},
		NodeIndex:     map[string]string{},
		IngStatistics: statistics.StatisticMap{},
		EgStatistics:  statistics.StatisticMap{},
	}

	// Start watching Pods and Nodes
	go server.WatchPods()
	go server.WatchNodes()

	reg := prometheus.NewRegistry()
	reg.MustRegister(server)
	server.Start(reg)
}
