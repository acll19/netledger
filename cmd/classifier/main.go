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

	go server.WatchPods()
	go server.WatchNodes()

	reg := prometheus.NewRegistry()
	reg.MustRegister(server)
	server.Start(reg)
}
