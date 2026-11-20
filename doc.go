// Package appattest verifies Apple App Attest attestations and assertions
// on a server, following Apple's "Validating apps that connect to your
// server".
//
// The package keeps no state. Issuing one-time challenges, storing keys and
// moving counters atomically are the caller's job; doing them is what stops
// replays.
package appattest
