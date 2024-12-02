package service

import (
	"context"
	"log"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/hown3d/kubernetes-kms-plugin/internal/stackit/kms"
	testkms "github.com/hown3d/kubernetes-kms-plugin/internal/stackit/kms/test"
	"github.com/stackitcloud/stackit-sdk-go/core/config"
	kmsservice "k8s.io/kms/pkg/service"
)

const (
	testKey = "project/keyring/key/version"
	plain   = "foo"
)

var svc *KMS

func TestMain(t *testing.M) {
	server := httptest.NewServer(testkms.NewKMSHandler())
	defer server.Close()

	apiClient, err := kms.NewAPIClient(config.WithEndpoint(server.URL), config.WithoutAuthentication())
	if err != nil {
		log.Fatalf("creating kms apiclient: %s", err)
	}
	svc = &KMS{
		key:       testKey,
		apiClient: apiClient,
	}
	os.Exit(t.Run())
}

func TestEncrypt(t *testing.T) {
	resp, err := svc.Encrypt(context.Background(), "", []byte(plain))
	if err != nil {
		t.Fatalf("error encrypting: %s", err)
	}
	if resp.KeyID != testKey {
		t.Fatalf("kmsservice returned different key. Want %s, got %s", testKey, resp.KeyID)
	}
	// TODO: Test encrypt, decrypt circle
}

func TestDecrypt(t *testing.T) {
	req := &kmsservice.DecryptRequest{
		KeyID:      testKey,
		Ciphertext: []byte("ciphertext"),
	}
	// TODO: Test encrypt, decrypt circle
	_, err := svc.Decrypt(context.Background(), "", req)
	if err != nil {
		t.Fatalf("error encrypting: %s", err)
	}
}
