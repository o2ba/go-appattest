// Package authdata reads App Attest authenticator data: the bytes Apple's
// attestations and the app's assertions carry, in WebAuthn's layout.
package authdata

import (
	"encoding/binary"
	"errors"
)

// attestedFlag marks authenticator data that carries the key's AAGUID and
// credential ID (attestations do, assertions don't).
const attestedFlag = 0x40

// Data is parsed authenticator data.
type Data struct {
	// RPIDHash is SHA-256 of the app ID (team + bundle ID).
	RPIDHash [32]byte
	// Flags are WebAuthn's flags byte.
	Flags byte
	// Counter is 0 in an attestation and goes up with every assertion.
	Counter uint32
	// AAGUID is "appattestdevelop", or "appattest" and seven zero bytes in
	// production. Only in attestations.
	AAGUID [16]byte
	// CredentialID is the key ID. Only in attestations.
	CredentialID []byte
}

// Parse reads b. Anything after the credential ID (the COSE key and
// extensions) isn't needed and is ignored.
func Parse(b []byte) (Data, error) {
	var d Data
	if len(b) < 37 {
		return d, errors.New("authenticator data shorter than 37 bytes")
	}
	copy(d.RPIDHash[:], b[:32])
	d.Flags = b[32]
	d.Counter = binary.BigEndian.Uint32(b[33:37])
	if d.Flags&attestedFlag == 0 {
		return d, nil
	}
	rest := b[37:]
	if len(rest) < 18 {
		return d, errors.New("authenticator data too short for attested credential data")
	}
	copy(d.AAGUID[:], rest[:16])
	n := int(binary.BigEndian.Uint16(rest[16:18]))
	if len(rest) < 18+n {
		return d, errors.New("credential ID longer than the authenticator data")
	}
	d.CredentialID = rest[18 : 18+n]
	return d, nil
}
