package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/acll19/netledger/internal/classifier"
	"github.com/acll19/netledger/internal/classifier/server"
	k8s "github.com/acll19/netledger/internal/kubernetes"
	"github.com/acll19/netledger/internal/log"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	logLevel   string
	configPath string
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

	snapshot, err := classifier.LoadConfigSnapshot(configPath)
	if err != nil {
		slog.Error("Error loading classifier config", "path", configPath, "error", err)
		os.Exit(1)
	}

	server, err := server.NewServer(clientset, snapshot)
	if err != nil {
		slog.Error("Error initializing classifier", "error", err)
		os.Exit(1)
	}

	go func() {
		if err := server.WatchConfig(ctx, configPath, 20*time.Second); err != nil {
			slog.Error("Error starting config watcher", "error", err)
		}
	}()

	go server.WatchPods()
	go server.WatchNodes()

	reg := prometheus.NewRegistry()
	reg.MustRegister(server)
	server.Start(ctx, reg)
}

func init() {
	flag.StringVar(&logLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	flag.StringVar(&configPath, "config", "/etc/netledger/config.yaml", "Path to classifier YAML config")
}
