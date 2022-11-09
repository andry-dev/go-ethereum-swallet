package hckeystore

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
)

const (
	keyLength      = 128
	version        = 1
	KeyStoreScheme = "coldkeystore"
)

type keyStore interface {
	GetKey(addr common.Address, filename string, auth string) (*ColdKey, error)

	StoreKey(filename string, key *ColdKey, auth string) error

	JoinPath(filename string) string
}

// ColdKey is the stateful keystore for the hot/cold wallet. It has a master
// secret key, a master public key, an incremental ID and a state.
type ColdKey struct {
	Address         common.Address
	MasterSecretKey *ecdsa.PrivateKey
	State           *big.Int

	// The current identifier used to derive the current session private key.
	// Needs to be synced with the hot wallet.
	CurrentDerivationID *big.Int
}

type HotKey struct {
	Address         common.Address
	MasterPublicKey *ecdsa.PublicKey
	State           *big.Int

	// The current identifier used to derive the current session secret key.
	// Needs to be synced with the hot wallet.
	CurrentDerivationID *big.Int
}

type SessionKey struct {
	Address    common.Address
	PrivateKey *ecdsa.PrivateKey
}

type plainColdKeyJSON struct {
	Address             string `json:"address"`
	PrivateKey          string `json:"privatekey"`
	State               string `json:"state"`
	CurrentDerivationID string `json:"derivationid"`
	Version             int    `json:"version"`
}

type plainHotKeyJSON struct {
	Address             string `json:"address"`
	PublicKey           string `json:"publickey"`
	State               string `json:"state"`
	CurrentDerivationID string `json:"derivationid"`
	Version             int    `json:"version"`
}

func (key *HotKey) String() string {
	return fmt.Sprintf("{mpk=%v, state=0x%v, id=0x%v}\n", key.MasterPublicKey, key.State.Text(16), key.CurrentDerivationID.Text(16))
}

func (key *ColdKey) String() string {
	return fmt.Sprintf("{msk=%v, state=0x%v, id=0x%v}\n", key.MasterSecretKey.D, key.State.Text(16), key.CurrentDerivationID.Text(16))
}

func (key *ColdKey) MarshalJSON() (j []byte, err error) {
	jsonStruct := plainColdKeyJSON{
		Address:             hex.EncodeToString(key.Address[:]),
		PrivateKey:          hex.EncodeToString(crypto.FromECDSA(key.MasterSecretKey)),
		State:               hex.EncodeToString(key.State.Bytes()),
		CurrentDerivationID: hex.EncodeToString(key.CurrentDerivationID.Bytes()),
		Version:             version,
	}

	j, err = json.Marshal(jsonStruct)
	return j, err

}

func (key *ColdKey) UnmarshalJSON(j []byte) (err error) {
	keyJSON := new(plainColdKeyJSON)
	err = json.Unmarshal(j, &keyJSON)
	if err != nil {
		return err
	}

	addr, err := hex.DecodeString(keyJSON.Address)
	if err != nil {
		return err
	}

	privateKey, err := crypto.HexToECDSA(keyJSON.PrivateKey)
	if err != nil {
		return err
	}

	state, err := hex.DecodeString(keyJSON.State)
	if err != nil {
		return err
	}

	currentID, err := hex.DecodeString(keyJSON.CurrentDerivationID)
	if err != nil {
		return err
	}

	key.Address = common.BytesToAddress(addr)
	key.MasterSecretKey = privateKey
	key.State = big.NewInt(0).SetBytes(state)
	key.CurrentDerivationID = big.NewInt(0).SetBytes(currentID)

	return nil

}

// Calculates an equivalent hot key for the current cold key.
// All the fields from the cold key are copied to avoid incidental data
// structures.
func (key ColdKey) CalculateHotKey() HotKey {
	hotKey := HotKey{}

	mpk := key.MasterSecretKey.PublicKey
	state := *key.State
	id := *key.CurrentDerivationID
	hotKey.MasterPublicKey = &mpk
	hotKey.State = &state
	hotKey.CurrentDerivationID = &id

	return hotKey
}

func newKey(randomness io.Reader) (*ColdKey, *HotKey, error) {
	state, err := rand.Int(randomness, math.BigPow(2, keyLength))
	if err != nil {
		return nil, nil, err
	}

	msk, err := ecdsa.GenerateKey(crypto.S256(), randomness)
	if err != nil {
		return nil, nil, err
	}

	coldKey := ColdKey{
		Address:             crypto.PubkeyToAddress(msk.PublicKey),
		State:               state,
		MasterSecretKey:     msk,
		CurrentDerivationID: big.NewInt(0),
	}

	mpk := msk.PublicKey

	hotState := *state
	hotKey := HotKey{
		Address:             crypto.PubkeyToAddress(mpk),
		State:               &hotState,
		MasterPublicKey:     &mpk,
		CurrentDerivationID: big.NewInt(0),
	}

	return &coldKey, &hotKey, nil
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

// Creates the hash of a message from a session public key.
func sessionMessageHash(pk *ecdsa.PublicKey, nonce *big.Int, message []byte) []byte {
	messageHashState := crypto.NewKeccakState()
	messageHashState.Write(pk.X.Bytes())
	messageHashState.Write(pk.Y.Bytes())
	messageHashState.Write(nonce.Bytes())
	messageHashState.Write(message)
	return messageHashState.Sum(nil)
}

// Signs a message with the session secret ECDSA key generated from
// RandSecretKey.
//
// Returns a pair composed of a nonce and the signature.
func SessionSign(sessionSecretKey *SessionKey, message []byte) (nonce *big.Int, sig []byte) {
	nonce, err := rand.Int(rand.Reader, math.BigPow(2, keyLength))
	if err != nil {
		panic(err)
	}

	pk := &sessionSecretKey.PrivateKey.PublicKey

	message = sessionMessageHash(pk, nonce, message)

	sig, err = crypto.Sign(message, sessionSecretKey.PrivateKey)
	if err != nil {
		panic(err)
	}

	return nonce, sig
}

// Verifies the signature of a message with the given session public key and nonce.
func SessionVerify(sessionPublicKey *ecdsa.PublicKey, nonce *big.Int, signature []byte, message []byte) bool {
	pk := sessionPublicKey
	message = sessionMessageHash(pk, nonce, message)

	// VerifySignature requires a SEC 1 encoded public key blob and a 64 byte
	// signature, so we convert those.
	pkblob := crypto.FromECDSAPub(pk)
	// Remove 1 byte from the signature to get [R || S] representation.
	signature = signature[:len(signature)-1]
	return crypto.VerifySignature(pkblob, message, signature)
}

func bigIntFromBytes(b []byte) *big.Int {
	return new(big.Int).SetBytes(b)
}

// Derives a session secret key for session identifier id.
//
// Returns the generated session secret key.
func (key *ColdKey) SKDer(id *big.Int) *SessionKey {
	blob := crypto.Keccak256(key.State.Bytes(), id.Bytes())
	randID, newState := bigIntFromBytes(blob[:16]), bigIntFromBytes(blob[16:])

	sessionSecretKey, err := RandSecretKey(key.MasterSecretKey, randID)
	if err != nil {
		panic(err)
	}

	key.CurrentDerivationID = id
	key.State = newState

	return &SessionKey{
		Address:    crypto.PubkeyToAddress(sessionSecretKey.PublicKey),
		PrivateKey: sessionSecretKey,
	}
}

// Derives a session public key for session identifier id.
//
// Returns the generated session public key.
func (key *HotKey) PKDer(id *big.Int) (sessionPublicKey *ecdsa.PublicKey) {
	blob := crypto.Keccak256(key.State.Bytes(), id.Bytes())
	randID, newState := bigIntFromBytes(blob[:16]), bigIntFromBytes(blob[16:])

	sessionPublicKey = RandPublicKey(key.MasterPublicKey, randID)

	key.CurrentDerivationID = id
	key.State = newState

	return sessionPublicKey
}

func storeNewKey(keystore keyStore, rand io.Reader, passphrase string) (*ColdKey, accounts.Account, error) {
	coldKey, _, err := newKey(rand)

	if err != nil {
		return nil, accounts.Account{}, err
	}

	a := accounts.Account{
		Address: coldKey.Address,
		URL:     accounts.URL{Scheme: KeyStoreScheme, Path: keystore.JoinPath(keyFileName(coldKey.Address))},
	}

	if err := keystore.StoreKey(a.URL.Path, coldKey, passphrase); err != nil {
		zeroKey(coldKey.MasterSecretKey)
		return nil, a, err
	}

	return coldKey, a, err
}

func keyFileName(keyAddr common.Address) string {
	ts := time.Now().UTC()
	return fmt.Sprintf("UTC--%s--%s", toISO8601(ts), hex.EncodeToString(keyAddr[:]))
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

func writeKeyFile(file string, content []byte) error {
	name, err := writeTemporaryKeyFile(file, content)
	if err != nil {
		return err
	}

	return os.Rename(name, file)
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

func zeroKey(k *ecdsa.PrivateKey) {
	b := k.D.Bits()
	for i := range b {
		b[i] = 0
	}
}
