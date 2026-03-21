package main

import (
	"context"
	"flag"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/acll19/netledger/internal/classifier/server"
	k8s "github.com/acll19/netledger/internal/kubernetes"
	"github.com/acll19/netledger/internal/log"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	serviceCidr string
	logLevel    string
)

func main() {
	flag.Parse()
	log.SetupLogger(logLevel)

	clientset, err := k8s.GetKubernetesClient()
	if err != nil {
		slog.Error("Error creating Kubernetes client", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	_, ipNet, err := net.ParseCIDR(serviceCidr)
	if err != nil {
		slog.Error("Error parsing service CIDR", "error", err)
		os.Exit(1)
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
	flag.StringVar(&logLevel, "log-level", "info", "Log level (debug, info, warn, error)")
}
