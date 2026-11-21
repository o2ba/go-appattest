package appattest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func TestVerifyAssertion(t *testing.T) {
	d := &device{priv: newKeyPair(t)}
	var last uint32
	for i := 1; i <= 3; i++ {
		data := []byte("challenge\nPUT\n/v1/devices/1\n{}")
		got, err := VerifyAssertion(d.assert(t, testAppID, data), data, &d.priv.PublicKey, testAppID, last)
		if err != nil {
			t.Fatalf("assertion %d: %v", i, err)
		}
		if got != uint32(i) {
			t.Errorf("counter %d, want %d", got, i)
		}
		last = got
	}
}

func TestVerifyAssertionRejects(t *testing.T) {
	data := []byte("challenge\nPUT\n/v1/devices/1\n{}")
	d := &device{priv: newKeyPair(t)}
	signed := d.assert(t, testAppID, data)

	tests := []struct {
		name      string
		assertion []byte
		data      []byte
		key       *device
		appID     string
		last      uint32
		want      error
	}{
		{"other client data", signed, []byte("challenge\nPUT\n/v1/devices/2\n{}"), d, testAppID, 0, ErrSignature},
		{"other key", signed, data, &device{priv: newKeyPair(t)}, testAppID, 0, ErrSignature},
		{"other app", signed, data, d, "OTHERTEAM.com.example", 0, ErrAppID},
		{"replayed counter", signed, data, d, testAppID, 1, ErrCounter},
		{"older counter", signed, data, d, testAppID, 5, ErrCounter},
		{"not CBOR", []byte("nope"), data, d, testAppID, 0, ErrMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := VerifyAssertion(tt.assertion, tt.data, &tt.key.priv.PublicKey, tt.appID, tt.last)
			if !errors.Is(err, ErrInvalid) || !errors.Is(err, tt.want) {
				t.Errorf("got %v, want %v", err, tt.want)
			}
		})
	}
}

func TestVerifyAssertionNeedsAKey(t *testing.T) {
	if _, err := VerifyAssertion(nil, nil, nil, testAppID, 0); err == nil || errors.Is(err, ErrInvalid) {
		t.Errorf("nil key: %v", err)
	}
}

func FuzzVerifyAssertion(f *testing.F) {
	d := &device{priv: newKeyPair(f)}
	data := []byte("challenge\nPUT\n/\n")
	f.Add(d.assert(f, testAppID, data))
	f.Add([]byte{0xa0})
	other := newKeyPair(f)
	f.Fuzz(func(t *testing.T, raw []byte) {
		if _, err := VerifyAssertion(raw, data, &other.PublicKey, testAppID, 0); err == nil {
			t.Error("assertion passed with a key that never signed")
		} else if !errors.Is(err, ErrInvalid) {
			t.Errorf("error doesn't wrap ErrInvalid: %v", err)
		}
	})
}

// device is the app's side of assertions: a Secure Enclave key and its
// counter.
type device struct {
	priv    *ecdsa.PrivateKey
	counter uint32
}

// assert signs clientData the way generateAssertion does.
func (d *device) assert(t testing.TB, appID string, clientData []byte) []byte {
	t.Helper()
	d.counter++
	rp := sha256.Sum256([]byte(appID))
	authData := append(rp[:], 0x00)
	authData = binary.BigEndian.AppendUint32(authData, d.counter)

	cdh := sha256.Sum256(clientData)
	nonce := sha256.Sum256(append(bytes.Clone(authData), cdh[:]...))
	digest := sha256.Sum256(nonce[:])
	sig, err := ecdsa.SignASN1(rand.Reader, d.priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	raw, err := cbor.Marshal(assertionObject{Signature: sig, AuthenticatorData: authData})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
