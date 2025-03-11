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
	completeChain := flag.Bool("complete-chain", true, "Attempt to complete the chain with system root CAs")
	systemRootsOnly := flag.Bool("system-roots-only", false, "Only use system root CAs (ignore server-provided chain)")
	flag.Parse()

	// Validate required flags
	if *host == "" {
		fmt.Fprintln(os.Stderr, "Error: host is required")
		flag.Usage()
		os.Exit(1)
	}

	// Connect to server and get certificates
	addr := fmt.Sprintf("%s:%s", *host, *port)
	certificates, err := getCertificateChain(addr, *completeChain, *systemRootsOnly)
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

func getCertificateChain(addr string, completeChain, systemRootsOnly bool) ([]*x509.Certificate, error) {
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

	// Get the certificate chain from the TLS connection
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}

	// If we only want system roots or don't need to complete the chain, return early
	if !completeChain {
		return certs, nil
	}

	// Get system root CAs
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("failed to load system root CAs: %w", err)
	}

	// If we only want to validate using system roots, start with just the leaf certificate
	if systemRootsOnly {
		certs = certs[:1]
	}

	// Try to complete the chain up to the root CA
	completeCerts, err := completeChainToRoot(certs, rootCAs)
	if err != nil {
		// If we can't complete the chain, return what we have with a warning
		fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
		return certs, nil
	}

	return completeCerts, nil
}

func completeChainToRoot(certs []*x509.Certificate, rootCAs *x509.CertPool) ([]*x509.Certificate, error) {
	if len(certs) == 0 {
		return nil, fmt.Errorf("empty certificate chain")
	}

	// Start with the provided chain
	completeCerts := make([]*x509.Certificate, len(certs))
	copy(completeCerts, certs)

	// Check if the last cert in the chain is self-signed (potential root)
	lastCert := completeCerts[len(completeCerts)-1]
	if isRoot(lastCert) {
		return completeCerts, nil
	}

	// Try to build a verification chain to find the root
	leaf := completeCerts[0]
	intermediates := x509.NewCertPool()
	for _, cert := range completeCerts[1:] {
		intermediates.AddCert(cert)
	}

	opts := x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         rootCAs,
	}

	chains, err := leaf.Verify(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to verify certificate chain: %w", err)
	}

	// Find the longest chain, which should have the most complete path to root
	var longestChain []*x509.Certificate
	maxLength := 0
	
	for _, chain := range chains {
		if len(chain) > maxLength {
			maxLength = len(chain)
			longestChain = chain
		}
	}

	if maxLength == 0 {
		return nil, fmt.Errorf("no valid certificate chains found")
	}

	// Return the longest chain found
	return longestChain, nil
}

func isRoot(cert *x509.Certificate) bool {
	// A root certificate is usually self-signed (subject equals issuer)
	return cert.IsCA && cert.Subject.String() == cert.Issuer.String()
}

func writeCertificatePEM(w *os.File, cert *x509.Certificate, index int) error {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	
	certType := "Intermediate"
	if index == 0 {
		certType = "Leaf"
	} else if isRoot(cert) {
		certType = "Root CA"
	}
	
	fmt.Fprintf(w, "# Certificate %d (%s) - %s\n", index, getSummary(cert), certType)
	return pem.Encode(w, block)
}

func writeCertificateText(w *os.File, cert *x509.Certificate, index int) error {
	certType := "Intermediate"
	if index == 0 {
		certType = "Leaf"
	} else if isRoot(cert) {
		certType = "Root CA"
	}
	
	fmt.Fprintf(w, "Certificate %d (%s):\n", index, certType)
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
	
	// Is this a self-signed certificate?
	isSelfSigned := cert.Subject.String() == cert.Issuer.String()
	fmt.Fprintf(w, "  Self-signed: %t\n", isSelfSigned)
	
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