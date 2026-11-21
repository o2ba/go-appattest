// Package apple holds Apple's App Attestation Root CA.
package apple

import (
	"crypto/x509"
	_ "embed"
)

//go:embed root_ca.pem
var rootPEM []byte

// Roots returns a pool holding Apple's App Attestation Root CA, from
// https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem.
func Roots() *x509.CertPool {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(rootPEM) {
		panic("appattest: embedded root certificate doesn't parse")
	}
	return pool
}
