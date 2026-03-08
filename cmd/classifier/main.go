package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/acll19/netledger/internal/classifier/server"
	k8s "github.com/acll19/netledger/internal/kubernetes"
	"github.com/prometheus/client_golang/prometheus"
)

var serviceCidr string

func main() {
	flag.Parse()

	clientset, err := k8s.GetKubernetesClient()
	if err != nil {
		log.Fatalf("Error creating kubernetes client: %v", err)
	}

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	_, ipNet, err := net.ParseCIDR(serviceCidr)
	if err != nil {
		log.Fatalf("Error parsing service CIDR: %v", err)
	}
	server := server.NewServer(clientset, ipNet)

	go server.WatchPods()
	go server.WatchNodes()

	reg := prometheus.NewRegistry()
	reg.MustRegister(server)
	server.Start(ctx, reg)
}

func init() {
	flag.StringVar(&serviceCidr, "serviceCidr", "", "Cluster service IP range")
}
