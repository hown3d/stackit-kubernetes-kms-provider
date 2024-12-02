package main

import (
	"context"
	"flag"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"time"

	"github.com/hown3d/kubernetes-kms-plugin/internal/service"
)

var (
	listenAddr = flag.String("listen", "/var/run/kmsplugin/socket.sock", "path where to bind the unix socket")
	timeout    = flag.Duration("timeout", 10*time.Second, "timeout for the grpc server")
	region     = flag.String("region", "eu01", "STACKIT region to use")
	key        = flag.String("key", "", "key to use for Encrypt and decryption. Format is {projectId}/{keyRingId}/{keyId}/{version}")
)

func main() {
	flag.Parse()
	s, err := service.New(*key, *listenAddr, *timeout)
	if err != nil {
		slog.Error("creating service", "error", err)
		os.Exit(1)
	}
	slog.Info("registered kms service", "key", *key)

	slog.Info("serving", "addr", *listenAddr)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	// Initializing the server in a goroutine so that
	// it won't block the graceful shutdown handling below
	go func() {
		if err := s.ListenAndServe(); err != nil {
			log.Fatalf("listen: %s\n", err)
		}
	}()

	// Listen for the interrupt signal.
	<-ctx.Done()

	// Restore default behavior on the interrupt signal and notify user of shutdown.
	stop()
	log.Println("shutting down gracefully")
	s.Shutdown()
	s.Close()
}
