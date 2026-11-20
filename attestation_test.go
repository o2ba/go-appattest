package appattest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
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

const testAppID = "ABCDE12345.com.example.app"

var testNow = time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)

func newKeyPair(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func keyIDOf(t testing.TB, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	point, err := pub.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(point)
	return h[:]
}

func sign(t testing.TB, tmpl, parent *x509.Certificate, pub *ecdsa.PublicKey, parentKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// fakeApple plays Apple's attestation CA: a root, an intermediate, and a
// credential certificate per attestation with the nonce extension.
type fakeApple struct {
	root, intermediate *x509.Certificate
	intermediateKey    *ecdsa.PrivateKey
	roots              *x509.CertPool
}

func newFakeApple(t testing.TB) *fakeApple {
	t.Helper()
	rootKey := newKeyPair(t)
	a := &fakeApple{intermediateKey: newKeyPair(t)}
	ca := func(serial int64, name string) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
			NotBefore: testNow.Add(-time.Hour), NotAfter: testNow.Add(time.Hour),
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		}
	}
	rootTmpl := ca(1, "Test App Attestation Root CA")
	a.root = sign(t, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	a.intermediate = sign(t, ca(2, "Test App Attestation CA 1"), a.root, &a.intermediateKey.PublicKey, rootKey)
	a.roots = x509.NewCertPool()
	a.roots.AddCert(a.root)
	return a
}

// attestation is one attestKey result, with every field the checks look
// at open to change.
type attestation struct {
	appID      string
	counter    uint32
	aaguid     string
	credID     []byte
	nonce      []byte     // nil: the right one
	issuer     *fakeApple // nil: the receiver
	key        *ecdsa.PublicKey
	notAfter   time.Time // zero: an hour after testNow
	fmt        string    // empty: apple-appattest
	noNonceExt bool
}

func validAttestation(t testing.TB, priv *ecdsa.PrivateKey) attestation {
	return attestation{appID: testAppID, aaguid: aaguidDevelopment, credID: keyIDOf(t, &priv.PublicKey), key: &priv.PublicKey}
}

func (a *fakeApple) attest(t testing.TB, at attestation, clientDataHash []byte) []byte {
	t.Helper()
	rp := sha256.Sum256([]byte(at.appID))
	authData := append(rp[:], 0x41)
	authData = binary.BigEndian.AppendUint32(authData, at.counter)
	authData = append(authData, at.aaguid...)
	authData = binary.BigEndian.AppendUint16(authData, uint16(len(at.credID)))
	authData = append(authData, at.credID...)

	nonce := at.nonce
	if nonce == nil {
		n := sha256.Sum256(append(bytes.Clone(authData), clientDataHash...))
		nonce = n[:]
	}
	ext, err := asn1.Marshal(struct {
		Nonce []byte `asn1:"tag:1,explicit"`
	}{nonce})
	if err != nil {
		t.Fatal(err)
	}
	issuer := a
	if at.issuer != nil {
		issuer = at.issuer
	}
	notAfter := at.notAfter
	if notAfter.IsZero() {
		notAfter = testNow.Add(time.Hour)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "credential"},
		NotBefore: testNow.Add(-2 * time.Hour), NotAfter: notAfter,
	}
	if !at.noNonceExt {
		tmpl.ExtraExtensions = []pkix.Extension{{Id: nonceOID, Value: ext}}
	}
	cred := sign(t, tmpl, issuer.intermediate, at.key, issuer.intermediateKey)

	var obj attestationObject
	obj.Fmt = "apple-appattest"
	if at.fmt != "" {
		obj.Fmt = at.fmt
	}
	obj.AttStmt.X5C = [][]byte{cred.Raw, issuer.intermediate.Raw}
	obj.AttStmt.Receipt = []byte("receipt")
	obj.AuthData = authData
	raw, err := cbor.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (a *fakeApple) verifier() *Verifier {
	return &Verifier{AppIDs: []string{testAppID, testAppID + ".dev"}, Roots: a.roots, Now: func() time.Time { return testNow }}
}

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
