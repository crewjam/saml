// Command gosaml serves gosaml.dev: test SAML identity providers and
// service providers that anyone can create and configure, and an
// inspector that decodes SAML messages in the browser.
//
// Everything it stores is temporary: each IdP or SP is deleted a fixed
// time after it is created (GOSAML_TTL), and the database is deleted and
// recreated whenever the server starts.
//
// Configuration is by environment variable:
//
//	GOSAML_BASE_URL       the URL the server is reached at (default http://localhost:8080)
//	GOSAML_ADDR           the address to listen on (default :8080)
//	GOSAML_DB             the SQLite database file (default gosaml.db in the temporary directory)
//	GOSAML_TTL            how long an IdP or SP lives (default 24h)
//	GOSAML_MAX_INSTANCES  the most IdPs and SPs that may exist at once (default 5000)
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/crewjam/saml/tools/gosaml/server"
	"github.com/crewjam/saml/tools/gosaml/store"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(log); err != nil {
		log.Error("exiting", "err", err)
		os.Exit(1)
	}
}

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func run(log *slog.Logger) error {
	ttl, err := time.ParseDuration(env("GOSAML_TTL", "24h"))
	if err != nil {
		return err
	}
	maxInstances, err := strconv.Atoi(env("GOSAML_MAX_INSTANCES", "5000"))
	if err != nil {
		return err
	}
	dbPath := env("GOSAML_DB", filepath.Join(os.TempDir(), "gosaml.db"))

	// Start from nothing every time, even if the disk outlived the last
	// run: nothing here is meant to be kept.
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if err := os.Remove(dbPath + suffix); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	db, err := store.Open(dbPath)
	if err != nil {
		return err
	}
	defer db.Close() //nolint:errcheck // exiting

	srv, err := server.New(server.Config{
		BaseURL:      env("GOSAML_BASE_URL", "http://localhost:8080"),
		Store:        db,
		TTL:          ttl,
		MaxInstances: maxInstances,
		Logger:       log,
	})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if n, err := db.Reap(ctx); err != nil {
					log.Error("reap", "err", err)
				} else if n > 0 {
					log.Info("reaped expired instances", "count", n)
				}
			}
		}
	}()

	hs := &http.Server{
		Addr:              env("GOSAML_ADDR", ":8080"),
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	hs.RegisterOnShutdown(srv.CloseLive)
	errc := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", hs.Addr, "base_url", srv.BaseURL, "db", dbPath, "ttl", ttl)
		errc <- hs.ListenAndServe()
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return hs.Shutdown(shutdownCtx)
}
