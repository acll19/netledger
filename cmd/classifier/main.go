package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/acll19/netledger/internal/classifier"
	"github.com/acll19/netledger/internal/classifier/server"
	k8s "github.com/acll19/netledger/internal/kubernetes"
	"github.com/acll19/netledger/internal/log"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	logLevel string
)

func main() {
	flag.Parse()
	log.SetupLogger(logLevel)
	slog.Info("log level flag", "level", logLevel)

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

	config := loadConfig()
	server := server.NewServer(clientset, config)

	go server.WatchPods()
	go server.WatchNodes()

	reg := prometheus.NewRegistry()
	reg.MustRegister(server)
	server.Start(ctx, reg)
}

func init() {
	flag.StringVar(&logLevel, "log-level", "info", "Log level (debug, info, warn, error)")
}

func loadConfig() classifier.Config {
	config, err := classifier.LoadConfig(".config/config.yaml")
	if err != nil {
		slog.Debug("Error loading config", "error", err)
	}
	return config
}
