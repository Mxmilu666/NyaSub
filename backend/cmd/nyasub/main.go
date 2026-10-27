package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"nyasub/internal/config"
	"nyasub/internal/httpapi"
	"nyasub/internal/store"
)

var version = "dev"

func main() {
	// Ensure databases, WAL files and generated secrets are private by default.
	oldUmask := syscall.Umask(0o077)
	defer syscall.Umask(oldUmask)

	cfg, err := config.Load()
	if err != nil {
		slog.Error("invalid configuration", "error", err)
		os.Exit(1)
	}
	levelVar := new(slog.LevelVar)
	levelVar.Set(cfg.LogLevel)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: levelVar}))
	slog.SetDefault(logger)

	db, err := store.Open(cfg.DataDir)
	if err != nil {
		logger.Error("open database", "error", err)
		os.Exit(1)
	}
	if err := store.Migrate(db); err != nil {
		logger.Error("run migrations", "error", err)
		os.Exit(1)
	}
	sqlDB, err := db.DB()
	if err != nil {
		logger.Error("obtain database handle", "error", err)
		os.Exit(1)
	}
	defer sqlDB.Close()

	app := httpapi.New(cfg, db, logger, version, levelVar)
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           app.Router(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		logger.Info("nyasub starting", "listen", cfg.Listen, "base_url", cfg.BaseURL, "version", version, "data_dir", cfg.DataDir)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("http server failed", "error", err)
			stop()
		}
	}()

	<-ctx.Done()
	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
	}
	logger.Info("stopped")
}
