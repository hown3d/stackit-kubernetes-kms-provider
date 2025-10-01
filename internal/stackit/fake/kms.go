package stackitfake

import (
	"context"
	"log/slog"
	"strconv"
)

type KMSClient struct {
	store *keystore
}

func NewKMSClient() (*KMSClient, error) {
	store, err := newKeystore()
	if err != nil {
		return nil, err
	}

	return &KMSClient{
		store: store,
	}, nil
}

func (c *KMSClient) Encrypt(_ context.Context, projectId, _, keyRingId, keyId string, keyVersion int64, data []byte) ([]byte, error) {

	encrypted, err := c.store.encrypt(projectId+"/"+keyRingId+"/"+keyId+"/"+strconv.FormatInt(keyVersion, 10), data)
	if err != nil {
		slog.Error("encrypting with kms", "err", err)
		return nil, err
	}
	return encrypted, nil
}

func (c *KMSClient) Decrypt(ctx context.Context, projectId, region, keyRingId, keyId string, keyVersion int64, data []byte) ([]byte, error) {
	encrypted, err := c.store.decrypt(projectId+"/"+keyRingId+"/"+keyId+"/"+strconv.FormatInt(keyVersion, 10), data)

	if err != nil {
		slog.Error("decrypting with kms", "err", err)
		return nil, err
	}
	return encrypted, nil
}

func (c *KMSClient) CreateKey(key string) error {
	return c.store.addKey(key)
}
