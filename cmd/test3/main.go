package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"strings"
)

func main() {
	// CLI flags
	host := flag.String("host", "", "Host to connect to (required)")
	port := flag.String("port", "443", "Port to connect to (default: 443)")
	output := flag.String("output", "", "Output file (default: stdout)")
	format := flag.String("format", "pem", "Output format: pem, text (default: pem)")
	flag.Parse()

	// Validate required flags
	if *host == "" {
		fmt.Fprintln(os.Stderr, "Error: host is required")
		flag.Usage()
		os.Exit(1)
	}

	// Connect to server
	addr := fmt.Sprintf("%s:%s", *host, *port)
	certificates, err := getCertificateChain(addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Prepare output
	var output_file *os.File
	if *output == "" {
		output_file = os.Stdout
	} else {
		output_file, err = os.Create(*output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
			os.Exit(1)
		}
		defer output_file.Close()
	}

	// Output certificates
	for i, cert := range certificates {
		if i > 0 {
			fmt.Fprintln(output_file)
		}

		switch strings.ToLower(*format) {
		case "pem":
			err = writeCertificatePEM(output_file, cert, i)
		case "text":
			err = writeCertificateText(output_file, cert, i)
		default:
			fmt.Fprintf(os.Stderr, "Error: unsupported format '%s'\n", *format)
			os.Exit(1)
		}

		if err != nil {
			fmt.Fprintf(os.Stderr, "Error writing certificate: %v\n", err)
			os.Exit(1)
		}
	}
}

func getCertificateChain(addr string) ([]*x509.Certificate, error) {
	// Create a custom TLS config that keeps the certificate chain
	conf := &tls.Config{
		InsecureSkipVerify: true, // We're just fetching the cert chain, not validating
	}

	// Connect to the server
	conn, err := tls.Dial("tcp", addr, conf)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	// Get the certificate chain
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}

	return certs, nil
}

func writeCertificatePEM(w *os.File, cert *x509.Certificate, index int) error {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	
	fmt.Fprintf(w, "# Certificate %d (%s)\n", index, getSummary(cert))
	return pem.Encode(w, block)
}

func writeCertificateText(w *os.File, cert *x509.Certificate, index int) error {
	fmt.Fprintf(w, "Certificate %d:\n", index)
	fmt.Fprintf(w, "  Subject: %s\n", cert.Subject)
	fmt.Fprintf(w, "  Issuer: %s\n", cert.Issuer)
	fmt.Fprintf(w, "  Serial Number: %x\n", cert.SerialNumber)
	fmt.Fprintf(w, "  Valid from: %s\n", cert.NotBefore)
	fmt.Fprintf(w, "  Valid until: %s\n", cert.NotAfter)
	fmt.Fprintf(w, "  Signature Algorithm: %s\n", cert.SignatureAlgorithm)
	
	// Print SANs if present
	if len(cert.DNSNames) > 0 {
		fmt.Fprintf(w, "  DNS Names: %s\n", strings.Join(cert.DNSNames, ", "))
	}
	
	// Check if it's a CA certificate
	fmt.Fprintf(w, "  Is CA: %t\n", cert.IsCA)
	
	return nil
}

func getSummary(cert *x509.Certificate) string {
	cn := cert.Subject.CommonName
	if cn == "" {
		if len(cert.Subject.Organization) > 0 {
			return cert.Subject.Organization[0]
		}
		return "Unknown"
	}
	return cn
}