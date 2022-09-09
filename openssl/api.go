package openssl

import "C"
import (
	"crypto/x509"
	"fmt"
)

// ParsePKCS7 decodes the raw signature into an OpenSSL PKCS7 struct

// ResolvePKCS7 decodes the raw signature into an OpenSSL PKCS7 struct,
// and returns the intermediary and leaf certificates used for the signature
func ResolvePKCS7(data []byte) (p7 *Pkcs7, inter, leaf *x509.Certificate, err error) {

	if p7, err = parsePKCS7(data); err != nil {
		return
	}
	defer func() {
		if err != nil {
			p7.Free()
		}
	}()

	// Decode intermediate and leaf certificates

	const interCertIndex = 1
	const leafCertIndex = 0

	// C structs -> DER
	// TODO: check stack length
	interBio, leafBio := newBIO(), newBIO()
	defer interBio.Free()
	defer leafBio.Free()

	if err = p7.verifyBio(interBio, interCertIndex); err != nil {
		err = fmt.Errorf("intermediate cert : %s", opensslError().Error())
		return
	}
	if err = p7.verifyBio(leafBio, leafCertIndex); err != nil {
		err = fmt.Errorf("leaf cert : %s", opensslError().Error())
		return
	}

	// DER -> Go structs
	if inter, err = x509.ParseCertificate(interBio.ReadAll()); err != nil {
		err = fmt.Errorf("error decoding the intermediate certificate: %s", err.Error())
		return
	}
	if leaf, err = x509.ParseCertificate(leafBio.ReadAll()); err != nil {
		err = fmt.Errorf("error decoding the leaf certificate: %s", err.Error())
		return
	}

	return p7, inter, leaf, nil
}
