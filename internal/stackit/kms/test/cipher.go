package test

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

const keysize = 16

type keystore struct {
	keys map[string]cipher.Block
}

func newKeystore(keys []string) (*keystore, error) {
	k := &keystore{
		keys: make(map[string]cipher.Block, len(keys)),
	}
	for _, key := range keys {
		aesKey := []byte(key)
		if len(aesKey) > keysize {
			aesKey = aesKey[:keysize]
		}
		aesCipher, err := aes.NewCipher(aesKey)
		if err != nil {
			return nil, err
		}
		k.keys[key] = aesCipher
	}
	return k, nil
}

var errKeyNotFound error = errors.New("key not found")

func (s *keystore) encrypt(key string, plain []byte) ([]byte, error) {
	block, ok := s.keys[key]
	if !ok {
		return nil, errKeyNotFound
	}
	blockSize := block.BlockSize()
	ciphertext := make([]byte, blockSize+len(plain))
	iv := ciphertext[:blockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[blockSize:], plain)
	return ciphertext, nil
}

func (s *keystore) decrypt(key string, ciphertext []byte) ([]byte, error) {
	block, ok := s.keys[key]
	if !ok {
		return nil, errKeyNotFound
	}
	blockSize := block.BlockSize()
	if len(ciphertext) < blockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	// reserve slice with len of ciphertext without block
	plain := make([]byte, len(ciphertext)-blockSize)

	iv := ciphertext[:blockSize]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(plain, ciphertext[blockSize:])
	return plain, nil
}
