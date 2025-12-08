package service

import (
	"context"
	"log"
	"os"
	"testing"

	stackitfake "github.com/hown3d/kubernetes-kms-plugin/internal/stackit/fake"
	kmsservice "k8s.io/kms/pkg/service"
)

const (
	testKey = "project-id/keyring/key/1"
	plain   = "foo"
)

var svc *KMS

func TestMain(t *testing.M) {
	kmsClient, err := stackitfake.NewKMSClient()
	if err != nil {
		log.Fatalf("setup kms handler: %v", err)
	}
	err = kmsClient.CreateKey(testKey)
	if err != nil {
		log.Fatalf("setup kms handler: %v", err)
	}
	svc = &KMS{
		key:       testKey,
		kmsClient: kmsClient,
	}
	os.Exit(t.Run())
}

func TestKMSService(t *testing.T) {
	resp, err := svc.Encrypt(context.Background(), "", []byte(plain))
	if err != nil {
		t.Fatalf("error encrypting: %s", err)
	}
	if resp.KeyID != testKey {
		t.Fatalf("kmsservice returned different key. Want %s, got %s", testKey, resp.KeyID)
	}
	req := &kmsservice.DecryptRequest{
		KeyID:      testKey,
		Ciphertext: resp.Ciphertext,
	}
	respPlain, err := svc.Decrypt(context.Background(), "", req)
	if err != nil {
		t.Fatalf("error encrypting: %s", err)
	}
	if string(respPlain) != plain {
		t.Errorf("circle encrypt and decrypt resulted in different plaintexts. Got: %s, want: %s", respPlain, plain)
	}
}
