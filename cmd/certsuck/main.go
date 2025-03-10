package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/myhops/certutil"
)

type options struct {
	hostPort string
}

func printPEM(w io.Writer, cert *x509.Certificate) error {
	fmt.Fprintf(w, "    Subject: %s\n", cert.Subject)
	fmt.Fprintf(w, "    Issuer:  %s\n", cert.Issuer)

	block := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	if err := pem.Encode(w, &block); err != nil {
		return err
	}
	return nil
}

func printPEMChain(w io.Writer, chain []*x509.Certificate) error {
	for i, cert := range chain {
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  Certificate %d \n", i+1)
		if err := printPEM(w, cert); err != nil {
			return fmt.Errorf("error writing cert %d: %w", i, err)
		}
	}
	return nil
}

func printChain(w io.Writer, chain []*x509.Certificate) {
	for j, cert := range chain {
		fmt.Fprintf(w, "  Certificate %d:\n", j+1)
		fmt.Fprintf(w, "    Subject: %s\n", cert.Subject)
		fmt.Fprintf(w, "    Issuer: %s\n", cert.Issuer)
	}
}

func getHostPort(host string) (string, int, error) {
	port := 443
	parts := strings.Split(host, ":")
	if len(parts) > 2 {
		return "", 0, fmt.Errorf("bad host:port")
	}
	if len(parts) == 2 {
		p, err := strconv.Atoi(parts[1])
		if err != nil {
			return "", 0, fmt.Errorf("bad port number: %w", err)
		}
		port = p
	}
	return parts[0], port, nil
}

func run(host string) error {
	h, p, err := getHostPort(host)
	if err != nil {
		return err
	}

	chains, err := certutil.CAChainFrom(h, p)
	if err != nil {
		return err
	}
	fmt.Printf("found %d valid chains\n", len(chains))
	printChain(os.Stdout,  chains[0])
	printPEMChain(os.Stdout, chains[0])
	return nil
}

func main() {
	if len(os.Args) < 2 {
		log.Printf("need host:port as arg")
		os.Exit(1)
	}
	if err := run(os.Args[1]); err != nil {
		log.Printf("run error: %s", err.Error())
		os.Exit(2)
	}
}
