package paytokens

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/nooize/go-assist"
	"os"
)

func ParsePemPrivateKey(bytes []byte) (crypto.PrivateKey, error) {
	pool := append(make([]byte, 0), bytes...)
	for {
		block, rest := pem.Decode(pool)
		if block == nil {
			break
		}
		if block.Type == "PRIVATE KEY" {
			return assist.ParseX509PrivateKey(block.Bytes)
		}
		pool = rest
	}
	return nil, fmt.Errorf("no private key found")
}

func LoadPemPrivateKey(path string) (crypto.PrivateKey, error) {
	if len(path) == 0 {
		return nil, nil
	}
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePemPrivateKey(bytes)
}

func ParsePemCertificate(bytes []byte) (*tls.Certificate, error) {
	var cert tls.Certificate
	pool := append(make([]byte, 0), bytes...)
	for {
		block, rest := pem.Decode(pool)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, block.Bytes)
		} else {
			if pKey, err := assist.ParseX509PrivateKey(block.Bytes); err != nil {
				return nil, fmt.Errorf("fail to parse private key : %s", err.Error())
			} else {
				cert.PrivateKey = pKey
			}
		}
		pool = rest
	}
	if len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("no certificate found")
	}
	return &cert, nil
}

func LoadPemCertificate(path string) (*tls.Certificate, error) {
	if len(path) == 0 {
		return nil, nil
	}
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePemCertificate(bytes)
}

// ResolveCertificateExtension returns the value of a certificate extension if it exists
func ResolveCertificateExtension(cert *x509.Certificate, oid asn1.ObjectIdentifier) ([]byte, error) {

	if cert == nil {
		return nil, errors.New("nil certificate")
	}

	var res []byte
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oid) {
			continue
		}
		res = ext.Value
	}
	if res == nil {
		return nil, errors.New("extension not found")
	}

	return res, nil
}
