package tls_info

import (
	"context"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net"
	"net/http"
	"time"
)

type Certificate struct {
	CertPem            string `json:"cert_pem"`
	IsCA               bool   `json:"is_ca"`
	Issuer             string `json:"issuer"`
	NotAfter           string `json:"not_after"`
	NotBefore          string `json:"not_before"`
	PublicKeyAlgorithm string `json:"public_key_algorithm"`
	SerialNumber       string `json:"serial_number"`
	SHA1Fingerprint    string `json:"sha1_fingerprint"`
	SignatureAlgorithm string `json:"signature_algorithm"`
	Subject            string `json:"subject"`
	Version            int    `json:"version"`
}

type CertificatesResponse struct {
	Certificates     []Certificate `json:"certificates"`
	SHA1Fingerprints []string      `json:"sha1_fingerprints"`
}

// Helper function to retrieve a TLS certificate from a URL and return a list of parsed certificates
func TLSCertificatesFromURL(url string, dnsResolver string) (*CertificatesResponse, error) {
	// Set custom DNS resolver
	transport := &http.Transport{
		Dial: (&net.Dialer{
			Timeout:  30 * time.Second,
			Resolver: &net.Resolver{PreferGo: true, Dial: customDNSDialer(dnsResolver)},
		}).Dial,
	}

	// Create HTTP client with custom transport
	client := &http.Client{
		Transport: transport,
	}

	// Retrieve the certificate from the URL
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Iterate over resp.TLS.PeerCertificates and parse each certificate
	certs := make([]Certificate, 0)
	sha1Fingerprints := make([]string, 0)
	for _, rawCert := range resp.TLS.PeerCertificates {
		cert := parseCertificate(rawCert)
		certs = append(certs, cert)
		sha1Fingerprints = append(sha1Fingerprints, cert.SHA1Fingerprint)
	}

	response := &CertificatesResponse{
		Certificates:     certs,
		SHA1Fingerprints: sha1Fingerprints,
	}

	return response, nil
}

func parseCertificate(rawCert *x509.Certificate) Certificate {
	// Convert the certificate to PEM format
	pemCert := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: rawCert.Raw,
	})
	cert := Certificate{
		CertPem:            string(pemCert),
		IsCA:               rawCert.IsCA,
		Issuer:             rawCert.Issuer.String(),
		NotAfter:           rawCert.NotAfter.UTC().Format(time.RFC3339),
		NotBefore:          rawCert.NotBefore.UTC().Format(time.RFC3339),
		PublicKeyAlgorithm: rawCert.PublicKeyAlgorithm.String(),
		SerialNumber:       rawCert.SerialNumber.String(),
		SignatureAlgorithm: rawCert.SignatureAlgorithm.String(),
		Subject:            rawCert.Subject.String(),
		Version:            rawCert.Version,
	}

	cert.SHA1Fingerprint = calculateSHA1Fingerprint(rawCert)

	return cert
}

func calculateSHA1Fingerprint(cert *x509.Certificate) string {
	// Calculate SHA-1 hash of the certificate
	sha1Hash := sha1.Sum(cert.Raw)

	// Convert the hash to a hexadecimal string
	sha1Fingerprint := hex.EncodeToString(sha1Hash[:])

	return sha1Fingerprint
}

// Custom DNS resolver dialer function
func customDNSDialer(dnsResolver string) func(ctx context.Context, network, address string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		d := net.Dialer{}
		// Use custom DNS resolver for dialing
		conn, err := d.DialContext(ctx, "tcp", dnsResolver+":53")
		if err != nil {
			return nil, err
		}
		return conn, nil
	}
}
