package gpay

import (
	"crypto"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"github.com/nooize/paytokens"
	"strings"
)

const (
	EcV1            tokenProtocol = "ECv1"
	EcV2            tokenProtocol = "ECv2"
	EcV2SigningOnly tokenProtocol = "ECv2SigningOnly"
	GoogleSenderId                = "Google"
	Card            PaymentMethod = "CARD"
	TokenizedCard   PaymentMethod = "TOKENIZED_CARD"
	PanOnly         AuthMethod    = "PAN_ONLY"
	Cryptogram3ds   AuthMethod    = "CRYPTOGRAM_3DS"

	EnvMerchantId         = "GOOGLE_PAY_MERCHANT_ID"
	EnvMerchantPrivateKey = "GOOGLE_PAY_MERCHANT_PRIVATE_KEY"
	EnvRootSignedKetsFile = "GOOGLE_PAY_ROOT_SIGNED_KEYS_FILE"
)

// IGooglePayHandler is the interface for Google Pay handlers
type IGooglePayHandler interface {
	Decrypt([]byte) (*GooglePayToken, error)
	MerchantId() string
}

// IOption is the interface option functions used when create new handler instance
type IOption func(*googlePayHandler) error

// New create new google pay handler instance with custom parameters
func New(merchantId string, options ...IOption) (IGooglePayHandler, error) {
	handler := &googlePayHandler{merchantId: strings.TrimSpace(merchantId)}
	for _, option := range options {
		if err := option(handler); err != nil {
			return nil, err
		}
	}
	switch {
	case len(handler.merchantId) == 0:
		return nil, errors.New("merchant id not defined")
	case handler.merchantPrivateKey == nil:
		return nil, errors.New("merchant private key not defined")
	}
	return handler, nil
}

func Decrypt(data []byte) (*GooglePayToken, error) {
	if defHandler == nil {
		return nil, fmt.Errorf("default google pay not defined")
	}
	return defHandler.Decrypt(data)
}

// MerchantPrivateKey option func to define merchant private key
func MerchantPrivateKey(key *ecdsa.PrivateKey) IOption {
	return func(h *googlePayHandler) error {
		h.merchantPrivateKey = key
		return nil
	}
}

// MerchantPemPrivateKey option func to define merchant private key from pem encoded data
func MerchantPemPrivateKey(data []byte) IOption {
	return func(h *googlePayHandler) error {
		key, err := verifyPrivateKey(paytokens.ParsePemPrivateKey(data))
		if err != nil {
			return err
		}
		return MerchantPrivateKey(key)(h)
	}
}

// MerchantPrivateKeyLocation option func to define merchant private key from file
func MerchantPrivateKeyLocation(path string) IOption {
	return func(h *googlePayHandler) error {
		key, err := verifyPrivateKey(paytokens.LoadPemPrivateKey(path))
		if err != nil {
			return err
		}
		return MerchantPrivateKey(key)(h)
	}
}

func verifyPrivateKey(key crypto.PrivateKey, err error) (*ecdsa.PrivateKey, error) {
	if err != nil {
		return nil, fmt.Errorf("failed to parse ECDSA private key: %s", err.Error())
	}
	privateKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("not a ECDSA private key")
	}
	return privateKey, nil
}
