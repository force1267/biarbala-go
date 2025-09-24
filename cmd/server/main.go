package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/force1267/biarbala-go/pkg/config"
	"github.com/force1267/biarbala-go/pkg/logger"
	"github.com/force1267/biarbala-go/pkg/metrics"
	"github.com/force1267/biarbala-go/pkg/server"
	"github.com/force1267/biarbala-go/pkg/storage"
	"github.com/force1267/biarbala-go/pkg/upload"
	"github.com/force1267/biarbala-go/pkg/web"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		logrus.WithError(err).Fatal("Failed to load configuration")
	}

	// Initialize logger
	log, err := logger.New(cfg.Logging.Level, cfg.Logging.Format, cfg.Logging.Output)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to initialize logger")
	}

	log.Info("Starting Biarbala server...")

	// Initialize metrics
	m := metrics.New()

	// Start metrics server if enabled
	if cfg.Metrics.Prometheus.Enabled {
		metricsAddr := fmt.Sprintf(":%d", cfg.Metrics.Prometheus.Port)
		metricsServer := m.StartHTTPServer(metricsAddr)
		log.WithField("address", metricsAddr).Info("Started metrics server")

		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := metricsServer.Shutdown(ctx); err != nil {
				log.WithError(err).Error("Failed to shutdown metrics server")
			}
		}()
	}

	// Initialize storage
	storage, err := storage.NewMongoDBStorage(cfg)
	if err != nil {
		log.WithError(err).Fatal("Failed to initialize storage")
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := storage.Close(ctx); err != nil {
			log.WithError(err).Error("Failed to close storage connection")
		}
	}()

	// Initialize upload service
	uploadService := upload.NewUploadService(cfg, log.Logger, storage)

	// Initialize web service (for future use)
	_ = web.NewWebService(cfg, log.Logger, storage, m)

	// Initialize Biarbala service
	biarbalaService := server.NewBiarbalaService(cfg, log.Logger, storage, uploadService, m)

	// Initialize server
	srv := server.New(cfg, log.Logger, m, biarbalaService)

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start server
	if err := srv.Start(ctx); err != nil {
		log.WithError(err).Fatal("Failed to start server")
	}

	log.Info("Biarbala server started successfully")

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("Shutting down Biarbala server...")

	// Create shutdown context with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	// Stop server
	if err := srv.Stop(shutdownCtx); err != nil {
		log.WithError(err).Error("Failed to stop server gracefully")
		os.Exit(1)
	}

	log.Info("Biarbala server stopped successfully")
}
