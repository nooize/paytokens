package apay

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"github.com/nooize/paytokens"
	"github.com/pkg/errors"
	"strings"
	"time"
)

type applePayHandler struct {
	// merchant id provided in apple developer account
	merchantId string

	// merchant iIdentity Certificate
	merchantCertificate *tls.Certificate
	// payment Processing Certificate
	processingCertificate *tls.Certificate
}

func (m *applePayHandler) MerchantId() string {
	return m.merchantId
}

// merchantIdHash hashes m.config.MerchantIdentifier with SHA-256
func (m *applePayHandler) merchantIdHash() []byte {
	h := sha256.New()
	h.Write([]byte(m.merchantId))
	return h.Sum(nil)
}

func (m *applePayHandler) prepareCertificate(cert *tls.Certificate) error {
	switch {
	case cert.Certificate == nil:
		return errors.New("nil certificate")
	case cert.PrivateKey == nil:
		return errors.New("merchant key is empty")
	}

	// Parse the leaf certificate of the certificate chain
	leaf, err := paytokens.Leaf(cert)
	if err != nil {
		return errors.Wrap(err, "certificate parsing error")
	}

	if _, err := leaf.Verify(x509.VerifyOptions{}); err != nil {
		if wrapCertificateError(err) != nil {
			return err
		}
		// TODO: certs signed by apple are somehow recognized as self-signed,
		// probably we need to figure out how to properly configure CA chain in docker
		// for now just validate expiration period
		// TODO log error
		//logrus.WithError(err).Warning("cert recognized as self signed")

		now := time.Now()
		if now.After(leaf.NotAfter) || now.Before(leaf.NotBefore) {
			return errors.New("certificate is expired or not yet valid")
		}
	}

	extValue, err := paytokens.ResolveCertificateExtension(leaf, merchantIDHashOID)
	if err != nil {
		return errors.Wrap(err, "error finding the hash extension")
	}
	// First two bytes are "@."
	if len(extValue) != 66 {
		return errors.New("invalid hash length")
	}
	merchantIDString, err := hex.DecodeString(string(extValue[2:]))
	if err != nil {
		return errors.Wrap(err, "invalid hash hex")
	}

	if !bytes.Equal(merchantIDString, m.merchantIdHash()) {
		return errors.New("merchant id not match certificate")
	}

	return nil
}

// Decrypt decrypts the apple pay token
func (m *applePayHandler) Decrypt(input []byte) (*ApplePayToken, error) {
	t := new(encryptedToken)
	if err := json.Unmarshal(input, t); err != nil {
		return nil, err
	}

	// Verify the signature before anything
	if err := t.verifySignature(); err != nil {
		return nil, errors.Wrap(err, "invalid token signature")
	}

	var key []byte
	var err error
	switch t.PaymentData.Version {
	case ecV1:
		// Compute the encryption key for EC-based tokens
		key, err = func(data []byte) ([]byte, error) {
			// use the token 's ephemeral EC key, the processing
			// private key, and the merchant ID to compute the encryption key
			// It is only used for the EC_v1 format

			// parse the ephemeral public key in a PKPaymentToken
			i, err := x509.ParsePKIXPublicKey(data)
			if err != nil {
				return nil, errors.Wrap(err, "error parsing the public key")
			}
			pubKey, ok := i.(*ecdsa.PublicKey)
			if !ok {
				return nil, errors.New("invalid EC public key")
			}

			privKey, ok := m.processingCertificate.PrivateKey.(*ecdsa.PrivateKey)
			if !ok {
				return nil, errors.New("non-elliptic processing private key")
			}

			// computes the shared secret between an EC public key and a
			// EC private key, according to RFC5903 Section 9
			sharedSecret, _ := privKey.Curve.ScalarMult(pubKey.X, pubKey.Y, privKey.D.Bytes())

			// Final key derivation from the shared secret and the hash of the merchant ID
			// deriveEncryptionKey derives the symmetric encryption key of the token payload
			// from a ECDHE shared secret and a hash of the merchant ID
			// It uses the function described in NIST SP 800-56A, section 5.8.1
			// See https://developer.apple.com/library/content/documentation/PassKit/Reference/PaymentTokenJSON/PaymentTokenJSON.html#//apple_ref/doc/uid/TP40014929-CH8-SW2
			// SHA256( counter || sharedSecret || algorithm || partyU || partyV )
			h := sha256.New()
			h.Write([]byte{0, 0, 0, 1})
			h.Write(sharedSecret.Bytes())
			h.Write([]byte("\x0Did-aes256-GCM"))
			h.Write([]byte("Apple"))
			h.Write(m.merchantIdHash())

			return h.Sum(nil), nil

		}(t.PaymentData.Header.EphemeralPublicKey)

	case rsaV1:
		// Decrypt the encryption key for RSA-based tokens
		// uses the merchant's RSA processing key to decrypt the
		// encryption key stored in the token
		key, err = func(cipherText []byte) ([]byte, error) {
			if cipherText == nil {
				return nil, errors.New("empty key ciphertext")
			}

			privKey, ok := m.processingCertificate.PrivateKey.(*rsa.PrivateKey)
			if !ok {
				return nil, errors.New("processing key is not RSA")
			}

			hash := sha256.New()
			key, err := rsa.DecryptOAEP(hash, rand.Reader, privKey, cipherText, nil)
			if err != nil {
				return nil, errors.Wrap(err, "error decrypting the key")
			}

			return key, nil
		}(t.PaymentData.Header.WrappedKey)
	}
	if err != nil {
		return nil, errors.Wrap(err, "error retrieving the encryption key")
	}

	// Decrypt the token
	decrypted, err := func(data []byte) ([]byte, error) {

		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, errors.Wrap(err, "error creating the block cipher")
		}
		// Block size 16 mandated by Apple, works with the default 12
		aesGCM, _ := cipher.NewGCMWithNonceSize(block, 16)
		nonce := make([]byte, aesGCM.NonceSize())
		plaintext, err := aesGCM.Open(nil, nonce, data, nil)
		if err != nil {
			return nil, errors.Wrap(err, "error decrypting the data")
		}
		return plaintext, nil

	}(t.PaymentData.Data)
	if err != nil {
		return nil, errors.Wrap(err, "error decrypting the token")
	}

	token := new(ApplePayToken)
	if err := json.Unmarshal(decrypted, token); err != nil {
		return nil, err
	}

	return token, nil
}

func wrapCertificateError(err error) error {
	if errors.As(err, &x509.UnknownAuthorityError{}) || strings.Contains(err.Error(), "certificate is not permitted") {
		return nil
	}
	return err
}
