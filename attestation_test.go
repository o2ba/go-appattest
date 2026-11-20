package appattest

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestVerifyAttestation(t *testing.T) {
	apple := newFakeApple(t)
	priv := newKeyPair(t)
	cdh := sha256.Sum256([]byte("challenge"))

	got, err := apple.verifier().VerifyAttestation(apple.attest(t, validAttestation(t, priv), cdh[:]), keyIDOf(t, &priv.PublicKey), cdh[:])
	if err != nil {
		t.Fatal(err)
	}
	if !got.PublicKey.Equal(&priv.PublicKey) || got.AppID != testAppID || got.Environment != Development || string(got.Receipt) != "receipt" {
		t.Errorf("got %+v", got)
	}

	at := validAttestation(t, priv)
	at.appID, at.aaguid = testAppID+".dev", aaguidProduction
	got, err = apple.verifier().VerifyAttestation(apple.attest(t, at, cdh[:]), keyIDOf(t, &priv.PublicKey), cdh[:])
	if err != nil || got.AppID != testAppID+".dev" || got.Environment != Production {
		t.Errorf("got %+v, %v", got, err)
	}
}

func TestVerifyAttestationRejects(t *testing.T) {
	apple := newFakeApple(t)
	other := newFakeApple(t)
	priv := newKeyPair(t)
	cdh := sha256.Sum256([]byte("challenge"))
	otherCDH := sha256.Sum256([]byte("another challenge"))

	tests := []struct {
		name   string
		change func(*attestation)
		cdh    []byte
		keyID  []byte
		want   error
	}{
		{"other roots", func(a *attestation) { a.issuer = other }, nil, nil, ErrCertificate},
		{"expired certificate", func(a *attestation) { a.notAfter = testNow.Add(-time.Minute) }, nil, nil, ErrCertificate},
		{"other client data hash", nil, otherCDH[:], nil, ErrNonce},
		{"nonce extension wrong", func(a *attestation) { a.nonce = make([]byte, 32) }, nil, nil, ErrNonce},
		{"no nonce extension", func(a *attestation) { a.noNonceExt = true }, nil, nil, ErrMalformed},
		{"other key", func(a *attestation) { a.key = &newKeyPair(t).PublicKey }, nil, nil, ErrKeyID},
		{"other key id", nil, nil, make([]byte, 32), ErrKeyID},
		{"other app", func(a *attestation) { a.appID = "OTHERTEAM.com.example" }, nil, nil, ErrAppID},
		{"counter not 0", func(a *attestation) { a.counter = 1 }, nil, nil, ErrCounter},
		{"unknown aaguid", func(a *attestation) { a.aaguid = "somethingelse123" }, nil, nil, ErrEnvironment},
		{"other credential id", func(a *attestation) { a.credID = make([]byte, 32) }, nil, nil, ErrKeyID},
		{"other format", func(a *attestation) { a.fmt = "packed" }, nil, nil, ErrMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			at := validAttestation(t, priv)
			if tt.change != nil {
				tt.change(&at)
			}
			keyID, hash := keyIDOf(t, &priv.PublicKey), cdh[:]
			if tt.keyID != nil {
				keyID = tt.keyID
			}
			if tt.cdh != nil {
				hash = tt.cdh
			}
			_, err := apple.verifier().VerifyAttestation(apple.attest(t, at, cdh[:]), keyID, hash)
			if !errors.Is(err, ErrInvalid) || !errors.Is(err, tt.want) {
				t.Errorf("got %v, want %v", err, tt.want)
			}
		})
	}
}

func TestVerifyAttestationRejectsGarbage(t *testing.T) {
	for _, raw := range [][]byte{nil, []byte("nope"), {0xa0}} {
		if _, err := newFakeApple(t).verifier().VerifyAttestation(raw, make([]byte, 32), make([]byte, 32)); !errors.Is(err, ErrMalformed) {
			t.Errorf("%q: %v", raw, err)
		}
	}
}

// TestAppleGuideSample checks the attestation Apple publishes in
// "Validating apps that connect to your server" against Apple's real root.
// The sample was made with the raw challenge as the client data hash, and
// its key ID is its credential ID.
func TestAppleGuideSample(t *testing.T) {
	b64, err := os.ReadFile("testdata/apple_guide_attestation.b64")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b64)))
	if err != nil {
		t.Fatal(err)
	}
	keyID, _ := base64.StdEncoding.DecodeString("zgSY9YSD+7TaDXssY6WlOPVS1K3Lmk+pFhlcSWE+ZV0=")
	v := &Verifier{
		AppIDs: []string{"1234567890.com.example.myapp"},
		Now:    func() time.Time { return time.Date(2026, 4, 23, 18, 13, 12, 0, time.UTC) },
	}

	got, err := v.VerifyAttestation(raw, keyID, []byte("example_server_challenge"))
	if err != nil {
		t.Fatal(err)
	}
	if got.AppID != "1234567890.com.example.myapp" || got.Environment != Production || len(got.Receipt) == 0 {
		t.Errorf("got %+v", got)
	}

	if _, err := v.VerifyAttestation(raw, keyID, []byte("another_challenge")); !errors.Is(err, ErrNonce) {
		t.Errorf("other challenge: %v", err)
	}
	v.AppIDs = []string{"1234567890.com.example.other"}
	if _, err := v.VerifyAttestation(raw, keyID, []byte("example_server_challenge")); !errors.Is(err, ErrAppID) {
		t.Errorf("other app: %v", err)
	}
	v.AppIDs = []string{"1234567890.com.example.myapp"}
	v.Now = func() time.Time { return time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC) }
	if _, err := v.VerifyAttestation(raw, keyID, []byte("example_server_challenge")); !errors.Is(err, ErrCertificate) {
		t.Errorf("after expiry: %v", err)
	}
}

func TestAppleRoots(t *testing.T) {
	if !bytes.Contains(appleRootPEM, []byte("Apple App Attestation Root CA")) && !bytes.Contains(appleRootPEM, []byte("BEGIN CERTIFICATE")) {
		t.Fatal("no certificate embedded")
	}
	AppleRoots()
}
