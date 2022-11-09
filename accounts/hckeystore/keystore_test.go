package hckeystore

import (
	"testing"
)

const keysDirPath = "/tmp/eth_hckeys"

func TestAccountCreation(t *testing.T) {
	ks := ColdKeyStore{
		storage: keyStorePlain{keysDirPath: keysDirPath},
	}

	account, err := ks.NewAccount("hello")

	if err != nil {
		t.Fatalf("Account creation failed: %s", err)
	}

	if len(account.Address.Bytes()) == 0 {
		t.Fatalf("Address is empty")
	}
}

func TestKeyLoad(t *testing.T) {
	ks := ColdKeyStore{
		storage: keyStorePlain{keysDirPath: keysDirPath},
	}

	const passphrase = "hello"

	account, err := ks.NewAccount(passphrase)

	if err != nil {
		t.Fatalf("Error when creating account %v: %s", account.Address, err)
	}

	key, err := ks.storage.GetKey(account.Address, account.URL.Path, passphrase)

	if err != nil {
		t.Fatalf("Error when obtaining account %v: %s", account.Address, err)
	}

	t.Log(key)

}
