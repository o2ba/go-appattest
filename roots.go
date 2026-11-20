package appattest

import (
	"crypto/x509"
	_ "embed"
)

//go:embed apple_app_attestation_root_ca.pem
var appleRootPEM []byte

// AppleRoots returns a pool holding Apple's App Attestation Root CA, from
// https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem.
func AppleRoots() *x509.CertPool {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(appleRootPEM) {
		panic("appattest: embedded root certificate doesn't parse")
	}
	return pool
}
