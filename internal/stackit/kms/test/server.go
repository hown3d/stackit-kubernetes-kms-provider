package test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/go-faster/xor"
)

func NewKMSHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(
		"POST /v1alpha/projects/{project}/keyrings/{keyring}/keys/{keys}/versions/{version}/encrypt",
		encryptHandler,
	)
	mux.HandleFunc(
		"POST /v1alpha/projects/{project}/keyrings/{keyring}/keys/{keys}/versions/{version}/decrypt",
		decryptHandler,
	)
	return mux
}

type req struct {
	Data []byte `json:"data"`
}

type resp struct {
	Data []byte `json:"data"`
}

func encryptHandler(w http.ResponseWriter, r *http.Request) {
	paramKey := pathParametersFromRequest(r).hash()
	req := req{}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}

	baseReader := base64.NewDecoder(base64.RawStdEncoding, bytes.NewReader(req.Data))
	b, err := io.ReadAll(baseReader)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}

	cipher := encrypt(paramKey, b)
	buf := new(bytes.Buffer)
	baseWriter := base64.NewEncoder(base64.RawStdEncoding, buf)
	baseWriter.Write(cipher)
	baseWriter.Close()
	json.NewEncoder(w).Encode(resp{
		Data: buf.Bytes(),
	})
}

func decryptHandler(w http.ResponseWriter, r *http.Request) {
	paramKey := pathParametersFromRequest(r).hash()
	req := req{}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}

	baseReader := base64.NewDecoder(base64.RawStdEncoding, bytes.NewReader(req.Data))
	b, err := io.ReadAll(baseReader)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}
	plain := decrypt(paramKey, b)
	buf := new(bytes.Buffer)
	baseWriter := base64.NewEncoder(base64.RawStdEncoding, buf)
	baseWriter.Write(plain)
	baseWriter.Close()

	json.NewEncoder(w).Encode(resp{
		Data: buf.Bytes(),
	})
}

func encrypt(key, plain []byte) []byte {
	cipher := make([]byte, len(plain))
	xor.Bytes(cipher, plain, key)
	return cipher
}

func decrypt(key, cipher []byte) []byte {
	plain := make([]byte, len(cipher))
	xor.Bytes(plain, cipher, key)
	return plain
}

type pathParameters struct {
	projectID string
	keyringID string
	keyID     string
	version   string
}

func pathParametersFromRequest(r *http.Request) pathParameters {
	return pathParameters{
		projectID: r.PathValue("project"),
		keyringID: r.PathValue("keyring"),
		keyID:     r.PathValue("key"),
		version:   r.PathValue("version"),
	}
}

func (p pathParameters) hash() []byte {
	sha := sha256.New()
	fmt.Fprintf(sha, "%s/%s/%s/%s", p.projectID, p.keyringID, p.keyID, p.version)
	return sha.Sum(nil)
}
