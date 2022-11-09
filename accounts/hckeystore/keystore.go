package hckeystore

import (
	"crypto/rand"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/core/types"
	"math/big"
)

type ColdKeyStore struct {
	storage keyStore
}

type HotKeyStore struct {
}

func (ks *ColdKeyStore) NewAccount(passphrase string) (accounts.Account, error) {
	_, account, err := storeNewKey(ks.storage, rand.Reader, passphrase)

	if err != nil {
		return accounts.Account{}, err
	}

	return account, nil
}

func (ks *ColdKeyStore) SignHash(account accounts.Account, hash []byte) ([]byte, error) {
	return nil, nil
}

func (ks *ColdKeyStore) SignHashWithPassphrase(account accounts.Account, passphrase string, hash []byte) ([]byte, error) {
	return nil, nil
}

func (ks *ColdKeyStore) SignTx(account accounts.Account, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	return nil, nil
}

func (ks *ColdKeyStore) SignTxWithPassphrase(account accounts.Account, passphrase string, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	return nil, nil
}
