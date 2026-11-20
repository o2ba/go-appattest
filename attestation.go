package appattest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/o2ba/go-appattest/internal/apple"
	"github.com/o2ba/go-appattest/internal/authdata"
)

// AppleRoots returns a pool holding Apple's App Attestation Root CA.
func AppleRoots() *x509.CertPool { return apple.Roots() }

var nonceOID = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 2}

const (
	aaguidProduction  = "appattest\x00\x00\x00\x00\x00\x00\x00"
	aaguidDevelopment = "appattestdevelop"
)

// Environment is the App Attest environment a key was made in.
type Environment string

// Development keys come from builds with the development App Attest
// entitlement, so keep them apart from production ones.
const (
	Production  Environment = "production"
	Development Environment = "development"
)

// Attestation is what a verified attestation proves.
type Attestation struct {
	// PublicKey is the attested key. Store it, with AppID and a counter of
	// 0, to verify the app's assertions.
	PublicKey *ecdsa.PublicKey
	// AppID is the team ID + bundle ID the key was made for.
	AppID       string
	Environment Environment
	// Receipt is Apple's receipt, for fraud metric requests.
	Receipt []byte
}

// Verifier verifies attestations for a set of app IDs.
type Verifier struct {
	// AppIDs are the accepted team ID + bundle IDs, e.g.
	// "ABCDE12345.com.example.app". Required.
	AppIDs []string
	// Roots are the trusted roots. Nil means AppleRoots().
	Roots *x509.CertPool
	// Now returns the time certificates are checked at. Nil means time.Now.
	Now func() time.Time
}

// attestationObject is what DCAppAttestService.attestKey returns, in CBOR.
type attestationObject struct {
	Fmt     string `cbor:"fmt"`
	AttStmt struct {
		X5C     [][]byte `cbor:"x5c"`
		Receipt []byte   `cbor:"receipt"`
	} `cbor:"attStmt"`
	AuthData []byte `cbor:"authData"`
}

// VerifyAttestation checks an attestation object with Apple's nine steps.
// keyID is the raw key ID (generateKey returns it base64), and
// clientDataHash is what the app passed to attestKey: the SHA-256 of a
// one-time challenge the server issued. Every rejection wraps ErrInvalid;
// a Verifier without AppIDs is an error that doesn't.
func (v *Verifier) VerifyAttestation(attestation, keyID, clientDataHash []byte) (*Attestation, error) {
	if len(v.AppIDs) == 0 {
		return nil, errors.New("appattest: Verifier has no AppIDs")
	}
	var obj attestationObject
	if err := cbor.Unmarshal(attestation, &obj); err != nil {
		return nil, invalid(ErrMalformed, "attestation: %v", err)
	}
	if obj.Fmt != "apple-appattest" {
		return nil, invalid(ErrMalformed, "format %q", obj.Fmt)
	}

	// 1. The x5c chain, credential certificate first, verifies against the root.
	if len(obj.AttStmt.X5C) < 2 {
		return nil, invalid(ErrMalformed, "x5c needs the credential and intermediate certificates")
	}
	cred, err := x509.ParseCertificate(obj.AttStmt.X5C[0])
	if err != nil {
		return nil, invalid(ErrMalformed, "credential certificate: %v", err)
	}
	intermediates := x509.NewCertPool()
	for _, der := range obj.AttStmt.X5C[1:] {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, invalid(ErrMalformed, "intermediate certificate: %v", err)
		}
		intermediates.AddCert(cert)
	}
	roots, now := v.Roots, time.Now
	if roots == nil {
		roots = AppleRoots()
	}
	if v.Now != nil {
		now = v.Now
	}
	if _, err := cred.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime:   now(),
	}); err != nil {
		return nil, invalid(ErrCertificate, "%v", err)
	}

	// 2-4. The certificate's nonce is SHA-256(authData || clientDataHash).
	nonce := sha256.Sum256(append(bytes.Clone(obj.AuthData), clientDataHash...))
	certNonce, err := extensionNonce(cred)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(certNonce, nonce[:]) {
		return nil, invalid(ErrNonce, "attestation wasn't made for this client data hash")
	}

	// 5. The key ID is SHA-256 of the credential's public key.
	pub, ok := cred.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, invalid(ErrMalformed, "credential key is %T", cred.PublicKey)
	}
	point, err := pub.Bytes()
	if err != nil {
		return nil, invalid(ErrMalformed, "credential key: %v", err)
	}
	if hash := sha256.Sum256(point); !bytes.Equal(hash[:], keyID) {
		return nil, invalid(ErrKeyID, "key id isn't the hash of the credential's key")
	}

	data, err := authdata.Parse(obj.AuthData)
	if err != nil {
		return nil, invalid(ErrMalformed, "authenticator data: %v", err)
	}

	// 6. The RP ID hash is SHA-256 of one of our app IDs.
	appID := ""
	for _, id := range v.AppIDs {
		if data.RPIDHash == sha256.Sum256([]byte(id)) {
			appID = id
			break
		}
	}
	if appID == "" {
		return nil, invalid(ErrAppID, "not one of the accepted app IDs")
	}

	// 7. The counter is 0.
	if data.Counter != 0 {
		return nil, invalid(ErrCounter, "attestation counter is %d, want 0", data.Counter)
	}

	// 8. The AAGUID names the environment.
	var env Environment
	switch string(data.AAGUID[:]) {
	case aaguidProduction:
		env = Production
	case aaguidDevelopment:
		env = Development
	default:
		return nil, invalid(ErrEnvironment, "aaguid %q", data.AAGUID[:])
	}

	// 9. The credential ID is the key ID.
	if !bytes.Equal(data.CredentialID, keyID) {
		return nil, invalid(ErrKeyID, "credential id isn't the key id")
	}

	return &Attestation{PublicKey: pub, AppID: appID, Environment: env, Receipt: bytes.Clone(obj.AttStmt.Receipt)}, nil
}

// extensionNonce reads the nonce extension: a SEQUENCE holding
// [1] EXPLICIT OCTET STRING.
func extensionNonce(cert *x509.Certificate) ([]byte, error) {
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(nonceOID) {
			continue
		}
		var v struct {
			Nonce []byte `asn1:"tag:1,explicit"`
		}
		rest, err := asn1.Unmarshal(ext.Value, &v)
		if err != nil || len(rest) > 0 {
			return nil, invalid(ErrMalformed, "nonce extension: %v", err)
		}
		return v.Nonce, nil
	}
	return nil, invalid(ErrMalformed, "credential certificate has no nonce extension")
}
