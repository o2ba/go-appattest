// Package appattest verifies Apple App Attest attestations and assertions
// on a server, following Apple's "Validating apps that connect to your
// server".
//
// An app makes a key pair in the Secure Enclave and has Apple attest it once
// (DCAppAttestService.attestKey). The server checks that attestation with
// [Verifier.VerifyAttestation] and keeps the returned public key, app ID and
// a counter of 0. After that, the app signs requests with the key
// (generateAssertion); the server checks each one with [VerifyAssertion]
// against the stored key and counter, then stores the new counter.
//
// The package keeps no state. Issuing one-time challenges, storing keys and
// moving counters atomically are the caller's job; doing them is what stops
// replays.
//
// Only Go's standard crypto is used, plus github.com/fxamacker/cbor to
// decode CBOR. Apple's App Attestation Root CA is embedded.
package appattest
