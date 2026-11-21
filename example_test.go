package appattest_test

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"

	"github.com/o2ba/go-appattest"
)

// Registering a key: the app sends its key ID, the attestation and the
// challenge it attested with.
func ExampleVerifier_VerifyAttestation() {
	var keyID, attestation []byte // from the app, base64-decoded
	challenge := "one-time challenge your server issued and has now used up"

	v := &appattest.Verifier{AppIDs: []string{"ABCDE12345.com.example.app"}}
	clientDataHash := sha256.Sum256([]byte(challenge))
	a, err := v.VerifyAttestation(attestation, keyID, clientDataHash[:])
	if err != nil {
		fmt.Println("rejected")
		return
	}
	der, _ := x509.MarshalPKIXPublicKey(a.PublicKey)
	_ = der // store with a.AppID, a.Environment and counter 0, under keyID
	// Output: rejected
}

// Checking a signed request against the stored key and counter.
func ExampleVerifyAssertion() {
	var assertion []byte                                    // from the request, base64-decoded
	var key *ecdsa.PublicKey                                // stored at registration
	var lastCounter uint32                                  // stored, 0 after registration
	clientData := []byte("challenge\nPOST\n/v1/things\n{}") // rebuilt from the request

	counter, err := appattest.VerifyAssertion(assertion, clientData, key, "ABCDE12345.com.example.app", lastCounter)
	if err != nil {
		fmt.Println("rejected")
		return
	}
	_ = counter // store it, only if the stored counter is still lastCounter
	// Output: rejected
}
