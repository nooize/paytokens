package paytokens

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
)

func Leaf(c *tls.Certificate) (*x509.Certificate, error) {
	if c.Leaf == nil {
		cert, err := x509.ParseCertificate(c.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("certificate parse : %s", err.Error())
		}
		if !cert.IsCA {
			return nil, errors.New("the certificate seems not to be a CA")
		}
		c.Leaf = cert
	}
	return c.Leaf, nil
}
