package authdata

import (
	"bytes"
	"testing"
)

func TestParseAssertion(t *testing.T) {
	b := append(bytes.Repeat([]byte{1}, 32), 0x01, 0, 0, 1, 2)
	d, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if d.RPIDHash[0] != 1 || d.Counter != 258 || d.CredentialID != nil {
		t.Errorf("%+v", d)
	}
}

func TestParseAttestation(t *testing.T) {
	b := append(bytes.Repeat([]byte{1}, 32), 0x41, 0, 0, 0, 0)
	b = append(b, "appattestdevelop"...)
	b = append(b, 0, 3, 7, 8, 9, 0xa5)
	d, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if string(d.AAGUID[:]) != "appattestdevelop" || !bytes.Equal(d.CredentialID, []byte{7, 8, 9}) || d.Counter != 0 {
		t.Errorf("%+v", d)
	}
}

func TestParseRejectsShortData(t *testing.T) {
	for _, b := range [][]byte{
		make([]byte, 36),
		append(make([]byte, 32), 0x40, 0, 0, 0, 0, 1),
		append(append(make([]byte, 32), 0x40, 0, 0, 0, 0), append(make([]byte, 16), 0, 9, 1)...),
	} {
		if _, err := Parse(b); err == nil {
			t.Errorf("parsed %d bytes", len(b))
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add(append(bytes.Repeat([]byte{1}, 32), 0x41, 0, 0, 0, 0))
	f.Fuzz(func(t *testing.T, b []byte) {
		d, err := Parse(b)
		if err == nil && len(d.CredentialID) > len(b) {
			t.Error("credential id longer than the input")
		}
	})
}
