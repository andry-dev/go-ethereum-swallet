package hckeystore

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

const keyLength int64 = 128

// ColdKey is the stateful keystore for the hot/cold wallet. It has a master
// secret key, a master public key, an incremental ID and a state.
type ColdKey struct {
	MasterSecretKey *ecdsa.PrivateKey
	State           *big.Int
	ID              *big.Int
}

type HotKey struct {
	MasterPublicKey *ecdsa.PublicKey
	State           *big.Int
	ID              *big.Int
}

func (key *HotKey) String() string {
	return fmt.Sprintf("{mpk=%v, state=0x%v, id=0x%v}\n", key.MasterPublicKey, key.State.Text(16), key.ID.Text(16))
}

func (key *ColdKey) String() string {
	return fmt.Sprintf("{msk=%v, state=0x%v, id=0x%v}\n", key.MasterSecretKey.D, key.State.Text(16), key.ID.Text(16))
}

func Generate() (ColdKey, HotKey) {
	state, err := rand.Int(rand.Reader, math.BigPow(2, keyLength))
	if err != nil {
		panic(err)
	}

	msk, err := crypto.GenerateKey()
	if err != nil {
		panic(err)
	}

	coldKey := ColdKey{}
	coldKey.State = state
	coldKey.MasterSecretKey = msk
	coldKey.ID = big.NewInt(0)

	mpk := msk.PublicKey
	hotState := *state
	hotKey := HotKey{}
	hotKey.State = &hotState
	hotKey.MasterPublicKey = &mpk
	hotKey.ID = big.NewInt(0)

	return coldKey, hotKey
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
func SessionSign(sessionSecretKey *ecdsa.PrivateKey, message []byte) (nonce *big.Int, sig []byte) {
	nonce, err := rand.Int(rand.Reader, math.BigPow(2, keyLength))
	if err != nil {
		panic(err)
	}

	pk := &sessionSecretKey.PublicKey

	message = sessionMessageHash(pk, nonce, message)

	sig, err = crypto.Sign(message, sessionSecretKey)
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
// Returns the generated session secret key and the new state.
func (key *ColdKey) SKDer(id *big.Int) (sessionSecretKey *ecdsa.PrivateKey) {
	blob := crypto.Keccak256(key.State.Bytes(), id.Bytes())
	randID, newState := bigIntFromBytes(blob[:16]), bigIntFromBytes(blob[16:])

	sessionSecretKey, err := RandSecretKey(key.MasterSecretKey, randID)
	if err != nil {
		panic(err)
	}

	key.ID = id
	key.State = newState

	return sessionSecretKey
}

// Derives a session public key for session identifier id.
//
// Returns the generated session public key and the new state.
func (key *HotKey) PKDer(id *big.Int) (sessionPublicKey *ecdsa.PublicKey) {
	blob := crypto.Keccak256(key.State.Bytes(), id.Bytes())
	randID, newState := bigIntFromBytes(blob[:16]), bigIntFromBytes(blob[16:])

	sessionPublicKey = RandPublicKey(key.MasterPublicKey, randID)

	key.ID = id
	key.State = newState

	return sessionPublicKey
}

func (key *ColdKey) SignHash(account accounts.Account, hash []byte) ([]byte, error) {
	return nil, nil
}

func (key *ColdKey) SignHashWithPassphrase(account accounts.Account, passphrase string, hash []byte) ([]byte, error) {
	return nil, nil
}

func (key *ColdKey) SignTx(account accounts.Account, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	return nil, nil
}

func (key *ColdKey) SignTxWithPassphrase(account accounts.Account, passphrase string, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	return nil, nil
}
