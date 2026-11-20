package appattest

import (
	"crypto/sha256"
	"errors"
	"testing"
)

// FuzzVerifyAttestation checks that no input panics, and that anything
// rejected wraps ErrInvalid.
func FuzzVerifyAttestation(f *testing.F) {
	apple := newFakeApple(f)
	priv := newKeyPair(f)
	cdh := sha256.Sum256([]byte("challenge"))
	f.Add(apple.attest(f, validAttestation(f, priv), cdh[:]))
	f.Add([]byte{0xa0})
	v := apple.verifier()
	keyID := keyIDOf(f, &priv.PublicKey)
	f.Fuzz(func(t *testing.T, raw []byte) {
		if _, err := v.VerifyAttestation(raw, keyID, cdh[:]); err != nil && !errors.Is(err, ErrInvalid) {
			t.Errorf("error doesn't wrap ErrInvalid: %v", err)
		}
	})
}
