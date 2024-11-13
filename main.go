package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"time"

	stackitkms "github.com/hown3d/kubernetes-kms-plugin/internal/stackit/kms"
	"github.com/stackitcloud/stackit-sdk-go/core/config"
	kmsservice "k8s.io/kms/pkg/service"
)

var (
	listenAddr = flag.String("listen", "/var/run/kmsplugin/socket.sock", "path where to bind the unix socket")
	timeout    = flag.Duration("timeout", 10*time.Second, "timeout for the grpc server")
	region     = flag.String("region", "eu01", "STACKIT region to use")
	key        = flag.String("key", "", "key to use for Encrypt and decryption. Format is {projectId}/{keyRingId}/{keyId}/{version}")
)

type KMS struct {
	apiClient *stackitkms.APIClient
	key       string
}

// Decrypt implements service.Service.
func (k *KMS) Decrypt(ctx context.Context, uid string, req *kmsservice.DecryptRequest) ([]byte, error) {
	slog.Info("decrypting", "uid", uid)
	projectId, keyRingId, keyId, keyVersion, err := splitKey(req.KeyID)
	if err != nil {
		slog.Error("spliting key", "err", err)
		return nil, err
	}
	apiReq := stackitkms.DecryptRequest{
		ProjectID: projectId,
		KeyRingID: keyRingId,
		KeyID:     keyId,
		Version:   keyVersion,
		Data:      req.Ciphertext,
	}
	decrypted, err := k.apiClient.Decrypt(ctx, apiReq)
	if err != nil {
		slog.Error("decrypting with kms", "err", err)
		return nil, err
	}
	return io.ReadAll(decrypted)
}

// Encrypt implements service.Service.
func (k *KMS) Encrypt(ctx context.Context, uid string, data []byte) (*kmsservice.EncryptResponse, error) {
	slog.Info("encrypting", "uid", uid)
	projectId, keyRingId, keyId, keyVersion, err := splitKey(k.key)
	if err != nil {
		slog.Error("spliting key", "err", err)
		return nil, err
	}
	apiReq := stackitkms.EncryptRequest{
		ProjectID: projectId,
		KeyRingID: keyRingId,
		KeyID:     keyId,
		Version:   keyVersion,
		Data:      data,
	}
	enc, err := k.apiClient.Encrypt(ctx, apiReq)
	if err != nil {
		slog.Error("encrypting with kms", "err", err)
		return nil, err
	}
	defer enc.Close()
	cipher, err := io.ReadAll(enc)
	if err != nil {
		slog.Error("reading encryp response", "err", err)
		return nil, err
	}
	return &kmsservice.EncryptResponse{
		Ciphertext: cipher,
		KeyID:      k.key,
	}, nil
}

// Status implements service.Service.
func (k *KMS) Status(ctx context.Context) (*kmsservice.StatusResponse, error) {
	return &kmsservice.StatusResponse{
		Version: "v2",
		Healthz: "ok",
		KeyID:   k.key,
	}, nil
}

func splitKey(key string) (projectId, keyRingId, keyId, keyVersion string, err error) {
	splits := strings.Split(key, "/")
	if len(splits) != 4 {
		return "", "", "", "", fmt.Errorf("key is in unknown format: %s", key)
	}
	return splits[0], splits[1], splits[2], splits[3], nil
}

func main() {
	flag.Parse()
	apiClient, err := stackitkms.NewAPIClient(config.WithRegion(*region))
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
	kms := &KMS{
		key:       *key,
		apiClient: apiClient,
	}
	slog.Info("registered kms service", "key", *key)
	s := kmsservice.NewGRPCService(*listenAddr, *timeout, kms)
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
