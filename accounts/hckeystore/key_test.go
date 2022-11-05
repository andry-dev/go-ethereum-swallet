package hckeystore_test

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/hckeystore"
)

func TestSessionKeyDerivation(t *testing.T) {
	coldKey, hotKey := hckeystore.Generate()
	id := big.NewInt(2)
	sessionSecretKey := coldKey.SKDer(id)
	sessionPublicKey := hotKey.PKDer(id)

	if coldKey.State.Cmp(hotKey.State) != 0 {
		t.Fatalf("Mismatch in the state of the public and secret keys! Used ID: %v\n", id)
	}

	x1 := sessionSecretKey.X
	x2 := sessionPublicKey.X
	y1 := sessionSecretKey.Y
	y2 := sessionPublicKey.Y

	t.Logf("Session Secret Key Point: (%v, %v)", x1, y1)
	t.Logf("Session Public Key Point: (%v, %v)", x2, y2)

	if x1.Cmp(x2) != 0 {
		t.Fatalf("Mismatch in X points in ECDSA curve:\nsk:\t%v\npk:\t%v\n", x1, x2)
	}

	if y1.Cmp(y2) != 0 {
		t.Fatalf("Mismatch in Y points in ECDSA curve:\n\t%v\n\t%v\n", y2, y2)
	}
}

func TestSessionSign(t *testing.T) {
	coldKey, hotKey := hckeystore.Generate()
	id := big.NewInt(2)

	sessionSecretKey := coldKey.SKDer(id)
	sessionPublicKey := hotKey.PKDer(id)

	message := []byte("Hello")

	t.Logf("Message: %v", message)

	nonce, sig := hckeystore.SessionSign(sessionSecretKey, message)

	t.Logf("Nonce: %v", nonce)
	t.Logf("Signature: %v", sig)

	res := hckeystore.SessionVerify(sessionPublicKey, nonce, sig, message)

	if !res {
		t.Fatal("Signature mismatch!")
	}
}

func TestWrongSessionKeyShouldFailVerification(t *testing.T) {
	coldKey, hotKey := hckeystore.Generate()

	id1 := big.NewInt(2)
	id2 := big.NewInt(3)

	sessionSecretKey := coldKey.SKDer(id1)
	sessionPublicKey := hotKey.PKDer(id2)

	if coldKey.State.Cmp(hotKey.State) == 0 {
		t.Fatalf("Different session identifiers resulted in the same state.\nUsed ids: %v, %v", id1, id2)
	}

	x1 := sessionSecretKey.X
	x2 := sessionPublicKey.X

	if x1.Cmp(x2) == 0 {
		t.Fatal("Different session identifiers resulted in the same Xs in the secret and public keys.")
	}

	message := []byte("Hello")

	t.Logf("Message: %v", message)

	nonce, sig := hckeystore.SessionSign(sessionSecretKey, message)

	t.Logf("Nonce: %v", nonce)
	t.Logf("Signature: %v", sig)

	res := hckeystore.SessionVerify(sessionPublicKey, nonce, sig, message)

	if res {
		t.Fatal("Signature matched with different session keys.")
	}
}
