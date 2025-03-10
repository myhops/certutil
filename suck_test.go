package certutil

import (
	"crypto/x509"
	"testing"
)

func TestCAChainFrom(t *testing.T) {
	certs, err := CAChainFrom("www.google.com", 443)
	if err != nil {
		t.Fatalf("error: %s", err.Error())
	}
	_ = certs
	// Get the longest chain
	var c []*x509.Certificate
	for _, cc := range certs {
		if len(cc) > len(c) {
			c = cc
		}
	}
	t.Logf("%v", c)
}
