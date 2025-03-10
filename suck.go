package certutil

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
)

func CAChainFrom(host string, port int) ([][]*x509.Certificate, error) {

	var chains [][]*x509.Certificate

	vc := func(state tls.ConnectionState) error {
		chains = state.VerifiedChains
		return nil
	}

	config := &tls.Config{
		VerifyConnection: vc,
	}

	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", host, port), config)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.VerifyHostname(host); err != nil {
		return nil, err
	}
	return chains, nil
}
