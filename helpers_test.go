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
	"encoding/binary"
	"math/big"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

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
