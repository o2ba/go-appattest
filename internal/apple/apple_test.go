package apple

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestRoots(t *testing.T) {
	block, _ := pem.Decode(rootPEM)
	if block == nil {
		t.Fatal("no PEM block embedded")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if got := cert.Subject.CommonName; got != "Apple App Attestation Root CA" {
		t.Errorf("subject = %q", got)
	}
	Roots()
}
