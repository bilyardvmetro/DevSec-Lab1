package main

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bilyardvmetro/DevSec-Lab1/internal/api"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
func run() error {
	// Restrict newly created SQLite files to the current user.
	syscall.Umask(0077)
	key, err := base64.StdEncoding.DecodeString(os.Getenv("JWT_SECRET"))
	if err != nil {
		return errors.New("JWT_SECRET must be base64")
	}
	db, err := sql.Open("sqlite3", "file:lab.db?_foreign_keys=on&_busy_timeout=5000")
	if err != nil {
		return err
	}
	defer db.Close()
	app, err := api.New(db, key, os.Getenv("ADMIN_USERNAME"), os.Getenv("ADMIN_PASSWORD_HASH"))
	if err != nil {
		return err
	}
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("LISTEN_ADDR must be a loopback IP; use a TLS reverse proxy for remote access")
	}
	srv := &http.Server{Addr: addr, Handler: app.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 8192}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdown); err != nil {
			log.Print("shutdown failed")
		}
	}()
	log.Print("API listening on configured loopback address")
	err = srv.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
