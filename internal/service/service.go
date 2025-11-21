package service

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/hown3d/kubernetes-kms-plugin/internal/stackit"
	kmsservice "k8s.io/kms/pkg/service"
)

func New(key string, region string, address string, timeout time.Duration) (*kmsservice.GRPCService, error) {
	// Validate that key has valid syntax
	_, _, _, _, err := splitKey(key)
	if err != nil {
		return nil, err
	}

	kmsClient, err := stackit.NewKMSClient()
	if err != nil {
		return nil, err
	}

	kms := &KMS{
		key:       key,
		kmsClient: kmsClient,
		region:    region,
	}
	return kmsservice.NewGRPCService(address, timeout, kms), nil
}

type KMS struct {
	kmsClient stackit.KMSClient
	key       string
	region    string
}

// Decrypt implements service.Service.
func (k *KMS) Decrypt(ctx context.Context, uid string, req *kmsservice.DecryptRequest) ([]byte, error) {
	slog.Info("decrypting", "uid", uid)
	projectId, keyRingId, keyId, keyVersion, err := splitKey(req.KeyID)
	if err != nil {
		slog.Error("spliting key", "err", err)
		return nil, err
	}

	decrypted, err := k.kmsClient.Decrypt(ctx, projectId, k.region, keyRingId, keyId, keyVersion, req.Ciphertext)
	if err != nil {
		slog.Error("decrypting with kms", "err", err)
		return nil, err
	}
	return decrypted, nil
}

// Encrypt implements service.Service.
func (k *KMS) Encrypt(ctx context.Context, uid string, data []byte) (*kmsservice.EncryptResponse, error) {
	slog.Info("encrypting", "uid", uid)
	projectId, keyRingId, keyId, keyVersion, err := splitKey(k.key)
	if err != nil {
		slog.Error("spliting key", "err", err)
		return nil, err
	}

	encrypted, err := k.kmsClient.Encrypt(ctx, projectId, k.region, keyRingId, keyId, keyVersion, data)
	if err != nil {
		slog.Error("encrypting with kms", "err", err)
		return nil, err
	}
	return &kmsservice.EncryptResponse{
		Ciphertext: encrypted,
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

func splitKey(key string) (projectId, keyRingId, keyId string, keyVersion int64, err error) {
	splits := strings.Split(key, "/")
	if len(splits) != 4 {
		return "", "", "", 0, fmt.Errorf("key is in unknown format: %s", key)
	}

	version, err := strconv.Atoi(splits[3])
	if err != nil {
		return "", "", "", 0, err
	}
	return splits[0], splits[1], splits[2], int64(version), nil
}
