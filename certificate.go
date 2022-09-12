package paytokens

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
)

func Leaf(c *tls.Certificate) (*x509.Certificate, error) {
	if c.Leaf == nil {
		cert, err := x509.ParseCertificate(c.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("certificate parse : %s", err.Error())
		}
		c.Leaf = cert
	}
	return c.Leaf, nil
}
