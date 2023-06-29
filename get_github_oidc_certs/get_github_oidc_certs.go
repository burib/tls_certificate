package main

import (
	"encoding/json"
	"fmt"
	"github.com/burib/tls_certificate/tls_info"
	"log"
)

func main() {
	// Target URL
	url := "https://token.actions.githubusercontent.com/.well-known/openid-configuration"
	dnsResolver := "8.8.8.8"

	// Retrieve the certificates from the URL and parse them
	certsResponse, err := tls_info.TLSCertificatesFromURL(url, dnsResolver)
	if err != nil {
		log.Fatal(err)
	}

	// Convert certificates response to JSON
	jsonData, err := json.Marshal(certsResponse)
	if err != nil {
		log.Fatal(err)
	}

	// Print JSON data
	fmt.Println(string(jsonData))
}
