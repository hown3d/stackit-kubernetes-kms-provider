package service

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	stackitkms "github.com/hown3d/kubernetes-kms-plugin/internal/stackit/kms"
	kmsservice "k8s.io/kms/pkg/service"
)

func New(key string, address string, timeout time.Duration) (*kmsservice.GRPCService, error) {
	kmsClient, err := stackitkms.NewAPIClient()
	if err != nil {
		return nil, err
	}
	kms := &KMS{
		key:       key,
		apiClient: kmsClient,
	}
	return kmsservice.NewGRPCService(address, timeout, kms), nil
}

type KmsAPI interface{}

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
