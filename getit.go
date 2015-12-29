package main

import (
	"crypto/tls"
	"crypto/x509"
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
	response, err := cli.Get("https://aserver/users")
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
	// cert, err := tls.LoadX509KeyPair("/etc/chef/pivotal.crt", "/etc/chef/pivotal.pem")
	// if err != nil {
	// 	return nil, fmt.Errorf("error loading X509 key pair: %v", err)
	// }

	CA_Pool := x509.NewCertPool()
	severCert, err := ioutil.ReadFile("/Users/flexiant/.chef/trusted_certs/aserver.crt")
	if err != nil {
		return nil, fmt.Errorf("could not load CA file: %v", err)
	}
	CA_Pool.AppendCertsFromPEM(severCert)

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
