package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

func main() {
	// Connect to the remote server
	conn, err := tls.Dial("tcp", "remote-server.com:443", &tls.Config{
		InsecureSkipVerify: true, // Skip verification for demonstration purposes
	})
	if err != nil {
		fmt.Printf("Error connecting to server: %v\n", err)
		return
	}
	defer conn.Close()

	// Get the server's certificate chain
	certs := conn.ConnectionState().PeerCertificates

	// Print the certificate chain
	for i, cert := range certs {
		fmt.Printf("Certificate %d:\n", i)
		fmt.Printf("  Subject: %s\n", cert.Subject)
		fmt.Printf("  Issuer: %s\n", cert.Issuer)
		fmt.Printf("  Not Before: %s\n", cert.NotBefore)
		fmt.Printf("  Not After: %s\n", cert.NotAfter)
		fmt.Println()
	}

	// Load CA certificate
	caCert, err := os.ReadFile("path/to/ca-cert.pem")
	if err != nil {
		fmt.Printf("Error loading CA certificate: %v\n", err)
		return
	}

	// Create a CA certificate pool
	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
		fmt.Println("Failed to append CA certificate")
		return
	}

	// Verify the certificate chain
	opts := x509.VerifyOptions{
		Roots: caCertPool,
	}
	for _, cert := range certs {
		if _, err := cert.Verify(opts); err != nil {
			fmt.Printf("Failed to verify certificate: %v\n", err)
		} else {
			fmt.Println("Certificate verified successfully")
		}
	}
}
