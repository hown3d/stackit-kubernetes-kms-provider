package stackit

import (
	"context"
	"log/slog"

	stackitkms "github.com/stackitcloud/stackit-sdk-go/services/kms"
)

type KMSClient interface {
	Encrypt(ctx context.Context, projectId, region, keyRingId, keyId string, keyVersion int64, data []byte) ([]byte, error)
	Decrypt(ctx context.Context, projectId, region, keyRingId, keyId string, keyVersion int64, data []byte) ([]byte, error)
}

type STACKITKMSClient struct {
	apiClient *stackitkms.APIClient
}

func NewKMSClient() (*STACKITKMSClient, error) {
	kmsClient, err := stackitkms.NewAPIClient()
	if err != nil {
		return nil, err
	}
	return &STACKITKMSClient{
		apiClient: kmsClient,
	}, nil
}

func (c *STACKITKMSClient) Encrypt(ctx context.Context, projectId, region, keyRingId, keyId string, keyVersion int64, data []byte) ([]byte, error) {
	request := c.apiClient.Encrypt(ctx, projectId, region, keyRingId, keyId, keyVersion)
	request = request.EncryptPayload(stackitkms.EncryptPayload{Data: &data})

	encrypted, err := request.Execute()
	if err != nil {
		slog.Error("encrypting with kms", "err", err)
		return nil, err
	}
	return *encrypted.Data, nil
}

func (c *STACKITKMSClient) Decrypt(ctx context.Context, projectId, region, keyRingId, keyId string, keyVersion int64, data []byte) ([]byte, error) {
	request := c.apiClient.Decrypt(ctx, projectId, region, keyRingId, keyId, keyVersion)
	request = request.DecryptPayload(stackitkms.DecryptPayload{Data: &data})

	decrypted, err := request.Execute()
	if err != nil {
		slog.Error("decrypting with kms", "err", err)
		return nil, err
	}
	return *decrypted.Data, nil
}
