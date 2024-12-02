package test

import "testing"

func Test_cipher(t *testing.T) {
	key := []byte("foo")
	plain := []byte("bar")
	cipher := encrypt(key, plain)
	decPlain := decrypt(key, cipher)
	if string(decPlain) != string(plain) {
		t.Errorf("encrpyting and then decrypting the same input resulted in different output.\nPlain in: %s, Plain out: %s", plain, decPlain)
	}
}
