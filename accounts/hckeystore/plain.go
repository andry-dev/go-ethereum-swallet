package hckeystore

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/common"
)

type keyStorePlain struct {
	keysDirPath string
}

func (ks keyStorePlain) GetKey(addr common.Address, filename, passphrase string) (*ColdKey, error) {
	fd, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	defer fd.Close()

	key := new(ColdKey)
	if err := json.NewDecoder(fd).Decode(key); err != nil {
		return nil, err
	}

	if key.Address != addr {
		return nil, fmt.Errorf("key content mismatch: have address %x, want %x", key.Address, addr)
	}

	return key, nil
}

func (ks keyStorePlain) StoreKey(filename string, key *ColdKey, passphrase string) error {
	content, err := json.Marshal(key)
	if err != nil {
		return err
	}

	return writeKeyFile(filename, content)
}

func (ks keyStorePlain) JoinPath(filename string) string {
	if filepath.IsAbs(filename) {
		return filename
	}
	return filepath.Join(ks.keysDirPath, filename)
}
