package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/mrheiz97/stumpfworks-framework/core/app"
	"github.com/mrheiz97/stumpfworks-framework/core/config"
	"github.com/mrheiz97/stumpfworks-framework/core/logging"
	"github.com/mrheiz97/stumpfworks-framework/core/version"
	"github.com/mrheiz97/stumpfworks-framework/data/postgres"
	"github.com/mrheiz97/stumpfworks-framework/web/health"
	"github.com/mrheiz97/stumpfworks-framework/web/middleware"
)

func main() {
	configFile := flag.String("config", "", "path to JSON configuration file")
	httpAddress := flag.String("http-address", "", "HTTP listen address")
	flag.Parse()
	logger := logging.NewJSON(os.Stdout, slog.LevelInfo)
	cfg, err := config.LoadWithOverrides(config.Overrides{ConfigFile: *configFile, HTTPAddress: *httpAddress})
	if err != nil {
		logger.Error("configuration invalid", "error", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	build := version.Current()
	application, err := app.New(app.Options{Name: "minimal-app", Version: build.Version, Address: cfg.HTTP.Address, ReadTimeout: cfg.HTTP.ReadTimeout, ReadHeaderTimeout: cfg.HTTP.ReadHeaderTimeout, WriteTimeout: cfg.HTTP.WriteTimeout, IdleTimeout: cfg.HTTP.IdleTimeout, ShutdownTimeout: cfg.ShutdownTimeout, MaxHeaderBytes: cfg.HTTP.MaxHeaderBytes, Logger: logger})
	if err != nil {
		logger.Error("create application", "error", err)
		os.Exit(1)
	}
	healthHandler := health.New()
	if cfg.Postgres.URL != "" {
		database, err := postgres.Open(ctx, postgres.Options{URL: cfg.Postgres.URL, MaxConnections: cfg.Postgres.MaxConnections, MinConnections: cfg.Postgres.MinConnections, ConnectTimeout: cfg.Postgres.ConnectTimeout, MaxMessageBytes: cfg.Postgres.MaxMessageBytes, AllowInsecure: cfg.Postgres.AllowInsecure})
		if err != nil {
			logger.Error("database unavailable", "error", err)
			os.Exit(1)
		}
		if err := application.Use(database); err != nil {
			logger.Error("register database resource", "error", err)
			os.Exit(1)
		}
		if err := healthHandler.Register("postgres", database.Ping); err != nil {
			logger.Error("register database health check", "error", err)
			os.Exit(1)
		}
	}
	application.Handle("GET /health/live", http.HandlerFunc(healthHandler.Live))
	application.Handle("GET /health/ready", http.HandlerFunc(healthHandler.Ready))
	if err := application.UseHTTP(func(next http.Handler) http.Handler { return middleware.Chain(next, logger) }); err != nil {
		logger.Error("register HTTP middleware", "error", err)
		os.Exit(1)
	}
	limiter, err := middleware.LimitConcurrency(cfg.HTTP.MaxConcurrentRequests, cfg.HTTP.QueueTimeout)
	if err != nil {
		logger.Error("configure concurrency limit", "error", err)
		os.Exit(1)
	}
	if err := application.UseHTTP(limiter); err != nil {
		logger.Error("register concurrency limit", "error", err)
		os.Exit(1)
	}
	if err := application.Run(ctx); err != nil {
		logger.Error("application failed", "error", err)
		os.Exit(1)
	}
}
