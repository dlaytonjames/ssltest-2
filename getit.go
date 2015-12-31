package main

import (
	_ "crypto"
	_ "crypto/aes"
	_ "crypto/dsa"
	_ "crypto/ecdsa"
	_ "crypto/elliptic"
	_ "crypto/md5"
	_ "crypto/rsa"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"

	// "strings"
)

func main() {
	cli, err := httpClient()
	if err != nil {
		fmt.Printf("error creating http client: %v", err)
		return
	}
	response, err := cli.Get("https://api.staging.concerto.io:886//kaas/load_balancers")
	if err != nil {
		fmt.Printf("error on http request: %v", err)
		return
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Printf("error reading http request body: %v", err)
		return
	}

	fmt.Printf("Got: %s", body)
}

func httpClient() (*http.Client, error) {
	// Loads Clients Certificates and creates and 509KeyPair
	certPEM, err := ioutil.ReadFile("/tmp/server_cert.pem")
	if err != nil {
		return nil, fmt.Errorf("error loading X509 key pair: %v", err)
	}

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		panic("failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("failed to parse certificate: " + err.Error())
	}
	fmt.Printf("Alg: %v\n", cert.SignatureAlgorithm)

	CA_Pool := x509.NewCertPool()
	caCert, err := ioutil.ReadFile("/tmp/ca_cert.pem")
	if err != nil {
		return nil, fmt.Errorf("could not load CA file: %v", err)
	}
	ok := CA_Pool.AppendCertsFromPEM(caCert)
	if !ok {
		return nil, fmt.Errorf("could not load CA file: CA not correctly parsed")
	}

	//
	// Verify cert against known CA
	//
	vOpts := x509.VerifyOptions{Roots: CA_Pool}
	chains, err := cert.Verify(vOpts)
	if err != nil {
		fmt.Printf("failed to parse certificate: " + err.Error())
	}
	fmt.Printf("shains = %v\n", chains)

	// Creates a client with specific transport configurations
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: CA_Pool,
			// Certificates: []tls.Certificate{cert},
		},
	}

	client := &http.Client{Transport: transport}

	return client, nil
}
