package test

import (
	"testing"
)

var (
	testStore *keystore = newTestKeystore()
	testKeys            = []string{
		"3644BDE400C15E65ACCCD4DC67077889",
		"9C04CD84DD6BED8C066C1F9E08012BB7",
		"F9869C742F000B6C1671F3A3A7FE80CE",
	}
)

func Test_keystore(t *testing.T) {
	key := testKeys[0]
	plain := "foo"
	cipher, err := testStore.encrypt(key, []byte(plain))
	if err != nil {
		t.Fatalf("got error %s on store.encrypt(%s, %s) while not expecting one", err, key, plain)
	}
	decPlain, err := testStore.decrypt(key, cipher)
	if err != nil {
		t.Fatalf("got error %s on store.decrypt(%s, %s) while not expecting one", err, key, cipher)
	}
	if string(decPlain) != plain {
		t.Errorf("encrpyting and then decrypting the same input resulted in different output.\nPlain in: %s, len: %d, Plain out: %s, len: %d", plain, len(plain), decPlain, len(decPlain))
	}
}

func newTestKeystore() *keystore {
	store, err := newKeystore(testKeys)
	if err != nil {
		panic(err)
	}
	return store
}
