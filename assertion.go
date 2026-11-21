package appattest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"

	"github.com/fxamacker/cbor/v2"

	"github.com/o2ba/go-appattest/internal/authdata"
)

// assertionObject is what DCAppAttestService.generateAssertion returns, in
// CBOR.
type assertionObject struct {
	Signature         []byte `cbor:"signature"`
	AuthenticatorData []byte `cbor:"authenticatorData"`
}

// VerifyAssertion checks an assertion with Apple's steps and returns its
// counter, which the caller stores in place of lastCounter. clientData is
// the data the app hashed for generateAssertion, rebuilt on the server from
// the request; it must include a one-time challenge the server issued, and
// checking that challenge is the caller's job. Store the new counter only
// if the stored one is still lastCounter (a conditional write), so two
// requests can't both pass with the same assertion. Every rejection wraps
// ErrInvalid; a nil key is an error that doesn't.
func VerifyAssertion(assertion, clientData []byte, key *ecdsa.PublicKey, appID string, lastCounter uint32) (uint32, error) {
	if key == nil || key.Curve == nil {
		return 0, errors.New("appattest: no public key")
	}
	var obj assertionObject
	if err := cbor.Unmarshal(assertion, &obj); err != nil {
		return 0, invalid(ErrMalformed, "assertion: %v", err)
	}
	data, err := authdata.Parse(obj.AuthenticatorData)
	if err != nil {
		return 0, invalid(ErrMalformed, "authenticator data: %v", err)
	}

	// 1-3. The signature covers nonce = SHA-256(authenticatorData ||
	// SHA-256(clientData)); the Secure Enclave signs it with ECDSA-SHA256.
	clientDataHash := sha256.Sum256(clientData)
	nonce := sha256.Sum256(append(bytes.Clone(obj.AuthenticatorData), clientDataHash[:]...))
	digest := sha256.Sum256(nonce[:])
	if !ecdsa.VerifyASN1(key, digest[:], obj.Signature) {
		return 0, invalid(ErrSignature, "signature doesn't verify with the key")
	}

	// 4. The RP ID hash is SHA-256 of the key's app ID.
	if data.RPIDHash != sha256.Sum256([]byte(appID)) {
		return 0, invalid(ErrAppID, "assertion is for another app ID")
	}

	// 5. The counter went up.
	if data.Counter <= lastCounter {
		return 0, invalid(ErrCounter, "counter %d isn't above %d", data.Counter, lastCounter)
	}
	return data.Counter, nil
}
