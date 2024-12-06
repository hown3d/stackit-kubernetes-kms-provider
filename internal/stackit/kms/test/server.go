package test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

func NewKMSHandler(keys ...string) (http.Handler, error) {
	keystore, err := newKeystore(keys)
	if err != nil {
		return nil, fmt.Errorf("creating keystore from keys %v: %w", keys, err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc(
		"POST /v1alpha/projects/{project}/keyrings/{keyring}/keys/{key}/versions/{version}/encrypt",
		encryptHandler(keystore),
	)
	mux.HandleFunc(
		"POST /v1alpha/projects/{project}/keyrings/{keyring}/keys/{key}/versions/{version}/decrypt",
		decryptHandler(keystore),
	)
	return mux, nil
}

type req struct {
	Data []byte `json:"data"`
}

type resp struct {
	Data []byte `json:"data"`
}

func encryptHandler(store *keystore) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		keyID := pathParametersFromRequest(r).internalKeyID()
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

		cipher, err := store.encrypt(keyID, b)
		if err != nil {
			if errors.Is(err, errKeyNotFound) {
				w.WriteHeader(http.StatusNotFound)
			} else {
				w.WriteHeader(http.StatusInternalServerError)
			}
			w.Write([]byte(err.Error()))
			return
		}
		buf := new(bytes.Buffer)
		baseWriter := base64.NewEncoder(base64.RawStdEncoding, buf)
		baseWriter.Write(cipher)
		baseWriter.Close()
		json.NewEncoder(w).Encode(resp{
			Data: buf.Bytes(),
		})
	}
}

func decryptHandler(store *keystore) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		paramKey := string(pathParametersFromRequest(r).internalKeyID())
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
		plain, err := store.decrypt(paramKey, b)
		if err != nil {
			if errors.Is(err, errKeyNotFound) {
				w.WriteHeader(http.StatusNotFound)
			} else {
				w.WriteHeader(http.StatusInternalServerError)
			}
			w.Write([]byte(err.Error()))
			return
		}
		buf := new(bytes.Buffer)
		baseWriter := base64.NewEncoder(base64.RawStdEncoding, buf)
		baseWriter.Write(plain)
		baseWriter.Close()

		json.NewEncoder(w).Encode(resp{
			Data: buf.Bytes(),
		})
	}
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

func (p pathParameters) internalKeyID() string {
	return fmt.Sprintf("%s/%s/%s/%s", p.projectID, p.keyringID, p.keyID, p.version)
}
