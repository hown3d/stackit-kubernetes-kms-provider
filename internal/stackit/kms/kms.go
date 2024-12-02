package kms

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/stackitcloud/stackit-sdk-go/core/auth"
	"github.com/stackitcloud/stackit-sdk-go/core/config"
)

// NewConfiguration returns a new Configuration object
func NewConfiguration() *config.Configuration {
	cfg := &config.Configuration{
		DefaultHeader: make(map[string]string),
		Debug:         false,
		Servers: config.ServerConfigurations{
			{
				URL:         "https://kms.api.{region}qa.stackit.cloud",
				Description: "No description provided",
				Variables: map[string]config.ServerVariable{
					"region": {
						DefaultValue: "eu01",
						EnumValues: []string{
							"eu01",
						},
					},
				},
			},
		},
		OperationServers: map[string]config.ServerConfigurations{},
	}
	return cfg
}

// APIClient manages communication with the SKE-API API v1.1
// In most cases there should be only one, shared, APIClient.
type APIClient struct {
	cfg *config.Configuration
}

// NewAPIClient creates a new API client.
// Optionally receives configuration options
func NewAPIClient(opts ...config.ConfigurationOption) (*APIClient, error) {
	cfg := NewConfiguration()

	for _, option := range opts {
		err := option(cfg)
		if err != nil {
			return nil, fmt.Errorf("configuring the client: %w", err)
		}
	}

	err := config.ConfigureRegion(cfg)
	if err != nil {
		return nil, fmt.Errorf("configuring region: %w", err)
	}

	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{}
	}

	authRoundTripper, err := auth.SetupAuth(cfg)
	if err != nil {
		return nil, fmt.Errorf("setting up authentication: %w", err)
	}

	roundTripper := authRoundTripper
	if cfg.Middleware != nil {
		roundTripper = config.ChainMiddleware(roundTripper, cfg.Middleware...)
	}

	cfg.HTTPClient.Transport = roundTripper
	return &APIClient{
		cfg: cfg,
	}, nil
}

type EncryptRequest struct {
	ProjectID string
	KeyRingID string
	KeyID     string
	Version   string
	Data      []byte
}

func (a *APIClient) Encrypt(ctx context.Context, r EncryptRequest) (io.ReadCloser, error) {
	b := new(bytes.Buffer)
	encoder := base64.NewEncoder(base64.RawStdEncoding, b)
	_, err := io.Copy(encoder, bytes.NewReader(r.Data))
	if err != nil {
		return nil, err
	}
	encodedData, err := io.ReadAll(b)
	if err != nil {
		return nil, err
	}
	respBody, err := a.doRequest(ctx, "encrypt", r.ProjectID, r.KeyRingID, r.KeyID, r.Version, encodedData)
	if err != nil {
		return nil, err
	}
	return respBody, nil
}

type DecryptRequest struct {
	ProjectID string
	KeyRingID string
	KeyID     string
	Version   string
	Data      []byte
}

func (a *APIClient) Decrypt(ctx context.Context, r DecryptRequest) (io.Reader, error) {
	respBody, err := a.doRequest(ctx, "decrypt", r.ProjectID, r.KeyRingID, r.KeyID, r.Version, r.Data)
	if err != nil {
		return nil, err
	}
	decoder := base64.NewDecoder(base64.RawStdEncoding, respBody)
	return decoder, nil
}

func (a *APIClient) doRequest(ctx context.Context, method, projectId, keyRingId, keyId, version string, data []byte) (io.ReadCloser, error) {
	basePath, err := a.cfg.ServerURL(0, map[string]string{})
	if err != nil {
		return nil, err
	}
	path, err := url.JoinPath(basePath, "v1alpha", "projects", projectId, "keyrings", keyRingId, "keys", keyId, "versions", version, method)
	if err != nil {
		return nil, err
	}
	type reqBody struct {
		Data []byte `json:"data"`
	}
	body := reqBody{
		Data: data,
	}
	buf := new(bytes.Buffer)
	err = json.NewEncoder(buf).Encode(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", path, buf)
	if err != nil {
		return nil, err
	}
	req.Header["Content-Type"] = []string{"application/json"}
	resp, err := a.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("encryption was not successful: %s", respBody)
	}
	return resp.Body, nil
}
