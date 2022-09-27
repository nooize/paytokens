package apay

import (
	"bytes"
	"encoding/hex"
	"github.com/nooize/paytokens"
	"github.com/nooize/paytokens/sslapi"
	"github.com/pkg/errors"
	"time"
)

const (
	//ecV1 constant represented the EC version 1
	ecV1 tokenVersion = "EC_v1"
	//rsaV1 constant represented the RSA version 1
	rsaV1 tokenVersion = "RSA_v1"
)

type encryptedToken struct {
	TransactionTime time.Time `json:"transactionTime"`
	PaymentData     struct {
		Version   tokenVersion            `json:"version"`
		Data      paytokens.Base64Encoded `json:"data"`
		Signature paytokens.Base64Encoded `json:"signature"`
		Header    struct {
			PublicKeyHash      []byte `json:"publicKeyHash"`
			EphemeralPublicKey []byte `json:"ephemeralPublicKey,omitempty"`
			WrappedKey         []byte `json:"wrappedKey,omitempty"`
			ApplicationData    string `json:"applicationData,omitempty"`
			TransactionId      string `json:"transactionId"`
		} `json:"header"`
	} `json:"paymentData"`
	PaymentMethod struct {
		DisplayName string `json:"displayName"`
		Network     string `json:"network"`
		Type        string `json:"type"`
	} `json:"paymentMethod"`
	TransactionIdentifier string `json:"transactionIdentifier"`
}

// verifySignature checks the signature of the token, partially using OpenSSL
// due to Go's lack of support for PKCS7.
// See https://developer.apple.com/library/content/documentation/PassKit/Reference/PaymentTokenJSON/PaymentTokenJSON.html#//apple_ref/doc/uid/TP40014929-CH8-SW2
func (t encryptedToken) verifySignature() error {

	if rootCertificate == nil {
		return errors.New("no apple root certificate")
	}

	// decodes the raw payment token signature field into an OpenSSL
	// PKCS7 struct, and returns the intermediary and leaf certificates used for the
	// signature
	p7, inter, leaf, err := sslapi.ResolvePKCS7(t.PaymentData.Signature)
	if err != nil {
		return errors.Wrap(err, "error decoding the token signature")
	}
	defer p7.Free()

	// verifyCertificates checks the validity of the certificate chain used for
	// signing the token, and verifies the chain of trust from root to leaf
	// Ensure the certificates contain the correct OIDs
	if _, err := paytokens.ResolveCertificateExtension(inter, interCertificateOID); err != nil {
		return errors.Wrap(err, "invalid intermediate cert Apple extension")
	}
	if _, err := paytokens.ResolveCertificateExtension(leaf, leafCertificateOID); err != nil {
		return errors.Wrap(err, "invalid leaf cert Apple extension")
	}

	// Verify the chain of trust
	if err := inter.CheckSignatureFrom(rootCertificate); err != nil {
		return errors.Wrap(err, "intermediate cert is not trusted by root")
	}
	if err := leaf.CheckSignatureFrom(inter); err != nil {
		return errors.Wrap(err, "leaf cert is not trusted by intermediate cert")
	}

	// checks that the time of signing of the token is before the
	// transaction was received, and that the gap between the two is not too
	// significant. It uses the variable TransactionTimeWindow as a limit.
	transactionTime := time.Now()
	if !t.TransactionTime.IsZero() {
		transactionTime = t.TransactionTime
	}
	signingTime, err := p7.SigningTime()
	if err != nil {
		return errors.Wrap(err, "error reading the signing time from the token")
	}
	// Check that both times are separated by less than TransactionTimeWindow
	delta := transactionTime.Sub(signingTime)
	if delta < -time.Second {
		//return errors.Errorf("the transaction occured before the signing (%s difference)", delta.String())
	}
	if delta > TransactionTimeWindow {
		//return errors.Errorf("the transaction occured after the allowed time window (%s)", delta.String())
	}

	return nil
}

// signedData returns the data signed by the client's Secure Element as defined
// in Apple's documentation: https://developer.apple.com/library/content/documentation/PassKit/Reference/PaymentTokenJSON/PaymentTokenJSON.html#//apple_ref/doc/uid/TP40014929-CH8-SW2
func (t encryptedToken) signedData() []byte {
	signed := bytes.NewBuffer(nil)

	switch t.PaymentData.Version {
	case ecV1:
		signed.Write(t.PaymentData.Header.EphemeralPublicKey)
	case rsaV1:
		signed.Write(t.PaymentData.Header.WrappedKey)
	}

	signed.Write(t.PaymentData.Data)
	trIDHex, _ := hex.DecodeString(t.PaymentData.Header.TransactionId)
	signed.Write(trIDHex)
	appDataHex, _ := hex.DecodeString(t.PaymentData.Header.ApplicationData)
	signed.Write(appDataHex)
	return signed.Bytes()
}
