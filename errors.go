package appattest

import (
	"errors"
	"fmt"
)

// ErrInvalid is wrapped by every error that means the attestation or
// assertion doesn't prove a genuine app. The more specific errors below are
// wrapped with it.
var ErrInvalid = errors.New("appattest: invalid")

var (
	// ErrMalformed: not valid CBOR, or a field is missing or the wrong size.
	ErrMalformed = errors.New("malformed")
	// ErrCertificate: the certificate chain doesn't verify against the roots.
	ErrCertificate = errors.New("certificate chain")
	// ErrNonce: the attestation wasn't made for this client data hash.
	ErrNonce = errors.New("nonce mismatch")
	// ErrKeyID: the key ID isn't the hash of the attested public key.
	ErrKeyID = errors.New("key id mismatch")
	// ErrAppID: the authenticator data is for another app ID.
	ErrAppID = errors.New("app id mismatch")
	// ErrCounter: the attestation's counter isn't 0.
	ErrCounter = errors.New("counter")
	// ErrEnvironment: the AAGUID is neither production nor development.
	ErrEnvironment = errors.New("unknown environment")
)

func invalid(reason error, format string, args ...any) error {
	return fmt.Errorf("%w: %w: %s", ErrInvalid, reason, fmt.Sprintf(format, args...))
}
