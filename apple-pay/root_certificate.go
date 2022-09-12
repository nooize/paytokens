package apay

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
)

const (
	RootCertificateUrl = "https://www.apple.com/certificateauthority/AppleRootCA-G3.cer"
)

var (
	rootCertificate   *x509.Certificate
	rootCertificateMu = sync.RWMutex{}
)

func fetchRootCertificate() {
	rootCertificateMu.Lock()
	defer rootCertificateMu.Unlock()
	crt, err := fetchLocalRootCertificate(os.Getenv(envRootCertificatePath))
	if crt != nil {
		rootCertificate = crt
		return
	}
	if err != nil {
		log.Printf("load apple root certificate failed: %v", err.Error())
	}
	crt, err = fetchRootCertificateFromApple(RootCertificateUrl)
	if err != nil {
		log.Printf("load apple root certificate failed: %v", err.Error())
		return
	}
	rootCertificate = crt
}

func fetchRootCertificateFromApple(url string) (*x509.Certificate, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return parseRootCertificate(bytes)
}

func fetchLocalRootCertificate(path string) (*x509.Certificate, error) {
	if len(path) == 0 {
		return nil, nil
	}
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	pem, rest := pem.Decode(bytes)
	if pem == nil {
		return nil, errors.New("error decoding the root certificate")
	}
	if rest != nil && len(rest) > 0 {
		return nil, errors.New("trailing data after the root certificate")
	}

	return parseRootCertificate(pem.Bytes)
}

func parseRootCertificate(bytes []byte) (c *x509.Certificate, err error) {
	root, err := x509.ParseCertificate(bytes)
	if err != nil {
		return nil, errors.New("error decoding the root certificate parse: " + err.Error())
	}
	if !root.IsCA {
		return nil, errors.New("the certificate seems not to be a CA")
	}
	return root, nil
}
