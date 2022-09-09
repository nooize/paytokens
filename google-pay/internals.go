package gpay

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/crypto/hkdf"
	"io"
	"log"
	"math/big"
	"os"
	"strings"
)

const (
	// Minimum tag size in bytes. This provides minimum 80-bit security strength.
	minTagSizeInBytes = uint32(10)
	tagDigestSize     = uint32(32)
)

var (
	defHandler IGooglePayHandler
)

func init() {
	if err := func() error {
		merchantId := os.Getenv(EnvMerchantId)
		if merchantId = strings.TrimSpace(merchantId); len(merchantId) == 0 {
			return nil
		}
		keyPath := os.Getenv(EnvMerchantPrivateKey)
		if len(keyPath) == 0 {
			return nil
		}
		h, err := New(merchantId, MerchantPrivateKeyLocation(keyPath))
		if err != nil {
			return fmt.Errorf("env %s private key parse error: %s", EnvMerchantPrivateKey, err.Error())
		}
		defHandler = h
		return nil
	}(); err != nil {
		log.Printf(err.Error())
	}
	fetchRootSigningKeys()
}

func constructSignedData(args ...string) []byte {
	res := make([]byte, 0)
	for _, v := range args {
		vBytes := []byte(v)
		lBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(lBytes, uint32(len(vBytes)))
		res = append(res, lBytes...)
		res = append(res, vBytes...)
	}
	return res
}

func computeHKDF(key []byte, salt []byte, info []byte, tagSize uint32) ([]byte, error) {

	if tagSize > 255*tagDigestSize {
		return nil, fmt.Errorf("tag size too big")
	}
	if tagSize < minTagSizeInBytes {
		return nil, fmt.Errorf("tag size too small")
	}

	if len(salt) == 0 {
		salt = make([]byte, sha256.New().Size())
	}

	result := make([]byte, tagSize)
	kdf := hkdf.New(sha256.New, key, salt, info)
	n, err := io.ReadFull(kdf, result)
	if n != len(result) || err != nil {
		return nil, fmt.Errorf("compute of hkdf failed")
	}

	return result, nil
}

func parsePrivateKey(data []byte) (*ecdsa.PrivateKey, error) {
	key, err := x509.ParsePKCS8PrivateKey(data)
	if err != nil {
		return nil, errors.New("failed to parse ECDSA private key")
	}
	privateKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("not a ECDSA private key")
	}
	return privateKey, nil
}

func unmarshalPublicKey(data []byte) (*ecdsa.PublicKey, error) {
	x, y := elliptic.Unmarshal(elliptic.P256(), data)
	if x == nil {
		// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/os/pkcs11-curr-v2.40-os.html#_ftn1
		// PKCS#11 v2.20 specified that the CKA_EC_POINT was to be store in a DER-encoded
		// OCTET STRING.
		var point asn1.RawValue
		asn1.Unmarshal(data, &point)
		if len(point.Bytes) > 0 {
			x, y = elliptic.Unmarshal(elliptic.P256(), point.Bytes)
		}
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

func parsePublicKey(data []byte) (*ecdsa.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(data)
	if err != nil {
		return nil, errors.New("failed to parse ECDSA public key")
	}

	publicKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("Not a ECDSA public key")
	}

	return publicKey, nil
}

func verifySignature(key *ecdsa.PublicKey, data []byte, signature []byte) error {
	sign := struct {
		R *big.Int
		S *big.Int
	}{big.NewInt(0), big.NewInt(0)}
	if _, err := asn1.Unmarshal(signature, &sign); err != nil {
		return err
	}
	hash := sha256.Sum256(data)
	if !ecdsa.Verify(key, hash[:], sign.R, sign.S) {
		return errors.New("invalid signature")
	}
	return nil
}
