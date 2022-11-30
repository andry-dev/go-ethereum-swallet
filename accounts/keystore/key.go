// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package keystore

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"

	"github.com/vmihailenco/msgpack/v5"
)

const (
	version = 3
)

var (
	ErrNotDerivable       = errors.New("key not derivable: possibly already derived")
	ErrNoPrivateKey       = errors.New("key does not have a private key")
	ErrNoHotKeyGeneration = errors.New("can't generate hot key: key is hot or session")
)

type KeyType int8

const (
	ColdKeyType KeyType = iota
	HotKeyType
	SessionKeyType
	HotSessionKeyType
)

const stateLength = 16

type Key interface {
	Address() common.Address
	PrivateKey() (*ecdsa.PrivateKey, error)
	PublicKey() *ecdsa.PublicKey

	DerivePrivate(id []byte) (*SessionKey, error)
	DerivePublic(id []byte) (*HotSessionKey, error)
	GenerateHotKey() (*HotKey, error)
	PathIdentifier() string

	MarshalJSONSecure(auth string, scryptN, scryptP int) ([]byte, error)
}

type ColdKey struct {
	Id uuid.UUID // Version 4 "random" for unique id not derived from key data
	// to simplify lookups we also store the address
	address common.Address
	// we only store privkey as pubkey/address can be derived from it
	// privkey in this struct is always in plaintext
	MasterPrivateKey *ecdsa.PrivateKey

	State []byte
}

type HotKey struct {
	Id              uuid.UUID
	address         common.Address
	MasterPublicKey *ecdsa.PublicKey
	State           []byte
}

type SessionKey struct {
	Id         uuid.UUID
	address    common.Address
	privateKey *ecdsa.PrivateKey
}

type HotSessionKey struct {
	Id        uuid.UUID
	address   common.Address
	publicKey *ecdsa.PublicKey
}

type keyStore interface {
	// Loads and decrypts the key from disk.
	GetKey(addr common.Address, filename string, auth string) (Key, error)
	// Writes and encrypts the key.
	StoreKey(filename string, k Key, auth string) error
	// Joins filename with the key directory unless it is already absolute.
	JoinPath(filename string) string
}

type plainColdKeyJSON struct {
	Address    string `json:"address"`
	PrivateKey string `json:"privatekey"`
	Id         string `json:"id"`
	State      string `json:"state"`
	Version    int    `json:"version"`
}

type plainKeyJSONV3 struct {
	Address   string `json:"address"`
	PublicKey string `json:"publickey"`
	Id        string `json:"id"`
	KeyType   int    `json:"keytype"`
	Version   int    `json:"version"`
}

type encryptedHotKeyJSONV3 struct {
	Address   string     `json:"address"`
	PublicKey string     `json:"publickey"`
	Crypto    CryptoJSON `json:"crypto"`
	Id        string     `json:"id"`
	KeyType   int        `json:"keytype"`
	Version   int        `json:"version"`
}

type encryptedKeyJSONV3 struct {
	Address string     `json:"address"`
	Crypto  CryptoJSON `json:"crypto"`
	Id      string     `json:"id"`
	KeyType int        `json:"keytype"`
	Version int        `json:"version"`
}

type encryptedKeyJSONV1 struct {
	Address string     `json:"address"`
	Crypto  CryptoJSON `json:"crypto"`
	Id      string     `json:"id"`
	Version string     `json:"version"`
}

type CryptoJSON struct {
	Cipher       string                 `json:"cipher"`
	CipherText   string                 `json:"ciphertext"`
	CipherParams cipherparamsJSON       `json:"cipherparams"`
	KDF          string                 `json:"kdf"`
	KDFParams    map[string]interface{} `json:"kdfparams"`
	MAC          string                 `json:"mac"`
}

// Structure of ciphertext of the key and the state
// Used for encoding/decoding to/from msgpack so the ciphertext can be
// efficiently packed inside the JSON without writing custom binary formats.
type keyCiphertext struct {
	PrivateKey []byte
	State      []byte
}

type cipherparamsJSON struct {
	IV string `json:"iv"`
}

func (k *ColdKey) MarshalJSON() (j []byte, err error) {
	jStruct := plainColdKeyJSON{
		hex.EncodeToString(k.address[:]),
		hex.EncodeToString(crypto.FromECDSA(k.MasterPrivateKey)),
		k.Id.String(),
		hex.EncodeToString(k.State),
		version,
	}
	j, err = json.Marshal(jStruct)
	return j, err
}

func (k *ColdKey) UnmarshalJSON(j []byte) (err error) {
	keyJSON := new(plainColdKeyJSON)
	err = json.Unmarshal(j, &keyJSON)
	if err != nil {
		return err
	}

	u := new(uuid.UUID)
	*u, err = uuid.Parse(keyJSON.Id)
	if err != nil {
		return err
	}
	k.Id = *u
	addr, err := hex.DecodeString(keyJSON.Address)
	if err != nil {
		return err
	}
	privkey, err := crypto.HexToECDSA(keyJSON.PrivateKey)
	if err != nil {
		return err
	}

	state, err := hex.DecodeString(keyJSON.State)
	if err != nil {
		return err
	}

	k.address = common.BytesToAddress(addr)
	k.MasterPrivateKey = privkey
	k.State = state

	return nil
}

func newKeyFromECDSA(privateKeyECDSA *ecdsa.PrivateKey) *ColdKey {
	id, err := uuid.NewRandom()
	if err != nil {
		panic(fmt.Sprintf("Could not create random uuid: %v", err))
	}

	state := make([]byte, stateLength)
	_, err = rand.Read(state)
	if err != nil {
		panic(fmt.Sprintf("Could not create random state: %v", err))
	}

	key := &ColdKey{
		Id:               id,
		address:          crypto.PubkeyToAddress(privateKeyECDSA.PublicKey),
		MasterPrivateKey: privateKeyECDSA,
		State:            state,
	}
	return key
}

// NewKeyForDirectICAP generates a key whose address fits into < 155 bits so it can fit
// into the Direct ICAP spec. for simplicity and easier compatibility with other libs, we
// retry until the first byte is 0.
func NewKeyForDirectICAP(rand io.Reader) *ColdKey {
	randBytes := make([]byte, 64)
	_, err := rand.Read(randBytes)
	if err != nil {
		panic("key generation: could not read from random source: " + err.Error())
	}
	reader := bytes.NewReader(randBytes)
	privateKeyECDSA, err := ecdsa.GenerateKey(crypto.S256(), reader)
	if err != nil {
		panic("key generation: ecdsa.GenerateKey failed: " + err.Error())
	}
	key := newKeyFromECDSA(privateKeyECDSA)
	if !strings.HasPrefix(key.address.Hex(), "0x00") {
		return NewKeyForDirectICAP(rand)
	}
	return key
}

func newKey(rand io.Reader) (*ColdKey, error) {
	privateKeyECDSA, err := ecdsa.GenerateKey(crypto.S256(), rand)
	if err != nil {
		return nil, err
	}
	return newKeyFromECDSA(privateKeyECDSA), nil
}

func NewColdKey(uuid uuid.UUID, address common.Address, privateKey *ecdsa.PrivateKey) *ColdKey {
	state := make([]byte, stateLength)
	_, err := rand.Read(state)
	if err != nil {
		panic(fmt.Sprintf("Could not create random state: %v", err))
	}
	return &ColdKey{
		Id:               uuid,
		address:          address,
		MasterPrivateKey: privateKey,
		State:            state,
	}
}

func NewHotKey(uuid uuid.UUID, address common.Address, publicKey *ecdsa.PublicKey) *HotKey {
	state := make([]byte, stateLength)
	_, err := rand.Read(state)
	if err != nil {
		panic(fmt.Sprintf("Could not create random state: %v", err))
	}
	return &HotKey{
		Id:              uuid,
		address:         address,
		MasterPublicKey: publicKey,
		State:           state,
	}
}

func NewSessionKey(uuid uuid.UUID, address common.Address, privateKey *ecdsa.PrivateKey) *SessionKey {
	return &SessionKey{
		Id:         uuid,
		address:    address,
		privateKey: privateKey,
	}
}

// Creates a random ECDSA secret key from a master ECDSA secret key and an
// identifier.
// Effectively computes:
//      sk = msk * id mod P
func RandSecretKey(masterSecretKey *ecdsa.PrivateKey, id *big.Int) (*ecdsa.PrivateKey, error) {
	d := new(big.Int).Mul(masterSecretKey.D, id)
	d.Mod(d, masterSecretKey.Params().N)

	return crypto.ToECDSA(d.Bytes())
}

// Creates a random ECDSA public key from a master ECDSA public key and an
// identifier.
// Effectively computes:
//      pk = mpk * id
func RandPublicKey(masterPublicKey *ecdsa.PublicKey, id *big.Int) *ecdsa.PublicKey {
	pk := new(ecdsa.PublicKey)
	pk.Curve = masterPublicKey.Curve
	pk.X, pk.Y = masterPublicKey.ScalarMult(masterPublicKey.X, masterPublicKey.Y, id.Bytes())

	return pk
}

func bigIntFromBytes(b []byte) *big.Int {
	return new(big.Int).SetBytes(b)
}

func (k *ColdKey) Address() common.Address {
	return k.address
}

func (k *ColdKey) PrivateKey() (*ecdsa.PrivateKey, error) {
	return k.MasterPrivateKey, nil
}

func (k *ColdKey) PublicKey() *ecdsa.PublicKey {
	return &k.MasterPrivateKey.PublicKey
}

// Derives a session secret key for session identifier id.
//
// Returns the generated session secret key.
func (key *ColdKey) DerivePrivate(derivationId []byte) (*SessionKey, error) {
	blob := crypto.Keccak256(key.State, derivationId)
	randID, newState := bigIntFromBytes(blob[:16]), blob[16:]

	sessionSecretKey, err := RandSecretKey(key.MasterPrivateKey, randID)
	if err != nil {
		return nil, err
	}

	keyUUID, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	key.State = newState

	return &SessionKey{
		address:    crypto.PubkeyToAddress(sessionSecretKey.PublicKey),
		privateKey: sessionSecretKey,
		Id:         keyUUID,
	}, nil
}

func (k *ColdKey) DerivePublic(id []byte) (*HotSessionKey, error) {
	hotKey, _ := k.GenerateHotKey()
	return hotKey.DerivePublic(id)
}

// Calculates an equivalent hot key for the current cold key.
// All the fields from the cold key are copied to avoid incidental data
// structures.
func (k *ColdKey) GenerateHotKey() (*HotKey, error) {
	hotKey := HotKey{}

	mpk := k.MasterPrivateKey.PublicKey
	state := k.State
	hotKey.Id = k.Id
	hotKey.MasterPublicKey = &mpk
	hotKey.State = state
	hotKey.address = k.address

	return &hotKey, nil
}

func (k *ColdKey) PathIdentifier() string {
	return "COLD"
}

func (k *ColdKey) MarshalJSONSecure(auth string, scryptN, scryptP int) ([]byte, error) {
	plaintext := keyCiphertext{
		PrivateKey: math.PaddedBigBytes(k.MasterPrivateKey.D, 32),
		State:      k.State,
	}

	keyBytes, err := msgpack.Marshal(&plaintext)

	if err != nil {
		panic(err)
	}

	cryptoStruct, err := EncryptDataV3(keyBytes, []byte(auth), scryptN, scryptP)
	if err != nil {
		return nil, err
	}

	encryptedKeyJSONV3 := encryptedKeyJSONV3{
		hex.EncodeToString(k.address[:]),
		cryptoStruct,
		k.Id.String(),
		int(ColdKeyType),
		version,
	}
	return json.Marshal(encryptedKeyJSONV3)
}

func (k *HotKey) Address() common.Address {
	return k.address
}

func (k *HotKey) PrivateKey() (*ecdsa.PrivateKey, error) {
	return nil, ErrNoPrivateKey
}

func (k *HotKey) PublicKey() *ecdsa.PublicKey {
	return k.MasterPublicKey
}

func (k *HotKey) DerivePrivate(id []byte) (*SessionKey, error) {
	return nil, ErrNotDerivable
}

// Derives a session public key for session identifier id.
//
// Returns the generated session public key.
func (k *HotKey) DerivePublic(derivationId []byte) (*HotSessionKey, error) {
	blob := crypto.Keccak256(k.State, derivationId)
	randID, newState := bigIntFromBytes(blob[:16]), blob[16:]

	sessionPublicKey := RandPublicKey(k.MasterPublicKey, randID)

	k.State = newState

	keyUUID, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	sessionKey := &HotSessionKey{
		Id:        keyUUID,
		address:   crypto.PubkeyToAddress(*sessionPublicKey),
		publicKey: sessionPublicKey,
	}

	return sessionKey, nil
}

func (k *HotKey) GenerateHotKey() (*HotKey, error) {
	return nil, ErrNoHotKeyGeneration
}

func (k *HotKey) PathIdentifier() string {
	return "HOT"
}

func (k *HotKey) MarshalJSONSecure(auth string, scryptN, scryptP int) ([]byte, error) {
	plaintext := keyCiphertext{
		PrivateKey: []byte{}, // Hot key doesn't have a private key.
		State:      k.State,
	}

	keyBytes, err := msgpack.Marshal(plaintext)

	if err != nil {
		panic(err)
	}

	cryptoStruct, err := EncryptDataV3(keyBytes, []byte(auth), scryptN, scryptP)
	if err != nil {
		return nil, err
	}

	encryptedKeyJSONV3 := encryptedHotKeyJSONV3{
		Address:   hex.EncodeToString(k.address[:]),
		PublicKey: hex.EncodeToString(crypto.FromECDSAPub(k.MasterPublicKey)),
		Crypto:    cryptoStruct,
		Id:        k.Id.String(),
		KeyType:   int(HotKeyType),
		Version:   version,
	}
	return json.Marshal(encryptedKeyJSONV3)
}

func (k *SessionKey) Address() common.Address {
	return k.address
}

func (k *SessionKey) PrivateKey() (*ecdsa.PrivateKey, error) {
	return k.privateKey, nil
}

func (k *SessionKey) PublicKey() *ecdsa.PublicKey {
	return &k.privateKey.PublicKey
}

func (k *SessionKey) DerivePrivate(id []byte) (*SessionKey, error) {
	return nil, ErrNotDerivable
}

func (k *SessionKey) DerivePublic(id []byte) (*HotSessionKey, error) {
	return nil, ErrNotDerivable
}

func (k *SessionKey) GenerateHotKey() (*HotKey, error) {
	return nil, ErrNoHotKeyGeneration
}

func (k *SessionKey) PathIdentifier() string {
	return "SESSION"
}

func (k *SessionKey) MarshalJSONSecure(auth string, scryptN, scryptP int) ([]byte, error) {
	plaintext := keyCiphertext{
		PrivateKey: math.PaddedBigBytes(k.privateKey.D, 32),
		State:      []byte{},
	}

	keyBytes, err := msgpack.Marshal(plaintext)

	if err != nil {
		panic(err)
	}
	cryptoStruct, err := EncryptDataV3(keyBytes, []byte(auth), scryptN, scryptP)
	if err != nil {
		return nil, err
	}

	encryptedKeyJSONV3 := encryptedKeyJSONV3{
		Address: hex.EncodeToString(k.address[:]),
		Crypto:  cryptoStruct,
		Id:      k.Id.String(),
		KeyType: int(SessionKeyType),
		Version: version,
	}
	return json.Marshal(encryptedKeyJSONV3)
}
func writeTemporaryKeyFile(file string, content []byte) (string, error) {
	// Create the keystore directory with appropriate permissions
	// in case it is not present yet.
	const dirPerm = 0700
	if err := os.MkdirAll(filepath.Dir(file), dirPerm); err != nil {
		return "", err
	}
	// Atomic write: create a temporary hidden file first
	// then move it into place. TempFile assigns mode 0600.
	f, err := os.CreateTemp(filepath.Dir(file), "."+filepath.Base(file)+".tmp")
	if err != nil {
		return "", err
	}
	if _, err := f.Write(content); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", err
	}
	f.Close()
	return f.Name(), nil
}

func (k *HotSessionKey) Address() common.Address {
	return k.address
}

func (k *HotSessionKey) PrivateKey() (*ecdsa.PrivateKey, error) {
	return nil, ErrNoPrivateKey
}

func (k *HotSessionKey) PublicKey() *ecdsa.PublicKey {
	return k.publicKey
}

func (k *HotSessionKey) DerivePrivate(id []byte) (*SessionKey, error) {
	return nil, ErrNotDerivable
}

func (k *HotSessionKey) DerivePublic(id []byte) (*HotSessionKey, error) {
	return nil, ErrNotDerivable
}

func (k *HotSessionKey) GenerateHotKey() (*HotKey, error) {
	return nil, ErrNoHotKeyGeneration
}

func (k *HotSessionKey) PathIdentifier() string {
	return "HOT-SESSION"
}

func (k *HotSessionKey) MarshalJSONSecure(auth string, scryptN, scryptP int) ([]byte, error) {
	plainKey := plainKeyJSONV3{
		Address:   hex.EncodeToString(k.address[:]),
		PublicKey: hex.EncodeToString(crypto.FromECDSAPub(k.publicKey)),
		Id:        k.Id.String(),
		KeyType:   int(HotSessionKeyType),
		Version:   version,
	}

	return json.Marshal(plainKey)
}

func storeNewKey(ks keyStore, rand io.Reader, auth string) (Key, accounts.Account, error) {
	key, err := newKey(rand)
	if err != nil {
		return nil, accounts.Account{}, err
	}
	a := accounts.Account{
		Address: key.address,
		URL:     accounts.URL{Scheme: KeyStoreScheme, Path: ks.JoinPath(keyFileName(key.address, key.PathIdentifier()))},
	}
	if err := ks.StoreKey(a.URL.Path, key, auth); err != nil {
		zeroKey(key.MasterPrivateKey)
		return nil, a, err
	}
	return key, a, err
}

func writeKeyFile(file string, content []byte) error {
	name, err := writeTemporaryKeyFile(file, content)
	if err != nil {
		return err
	}
	return os.Rename(name, file)
}

// keyFileName implements the naming convention for keyfiles:
// UTC--<created_at UTC ISO8601>-<address hex>
func keyFileName(keyAddr common.Address, pathIdentifier string) string {
	ts := time.Now().UTC()
	return fmt.Sprintf("UTC--%s--%s--%s", toISO8601(ts), pathIdentifier, hex.EncodeToString(keyAddr[:]))
}

func toISO8601(t time.Time) string {
	var tz string
	name, offset := t.Zone()
	if name == "UTC" {
		tz = "Z"
	} else {
		tz = fmt.Sprintf("%03d00", offset/3600)
	}
	return fmt.Sprintf("%04d-%02d-%02dT%02d-%02d-%02d.%09d%s",
		t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), tz)
}
