package apay

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/nooize/pay-tokens"
	"net/url"
	"time"
)

const (
	// TransactionTimeWindow is the window of time, in minutes, where
	// transactions can fit to limit replay attacks
	TransactionTimeWindow = 5 * time.Minute
)

// IApplePayHandler is the interface for Apple Pay handlers
type IApplePayHandler interface {
	Decrypt([]byte) (*ApplePayToken, error)
	Session(ApplePaySessionURL, string, string) ([]byte, error)
	MerchantId() string
}

type IOption func(*applePayHandler) error

func New(merchantId string, options ...IOption) (IApplePayHandler, error) {
	handler := &applePayHandler{
		merchantId: merchantId,
	}
	for _, option := range options {
		if err := option(handler); err != nil {
			return nil, err
		}
	}
	switch {
	case len(handler.merchantId) == 0:
		return nil, errors.New("merchant id not defined")
	case handler.merchantCertificate == nil:
		return nil, errors.New("merchant certificate not defined")
	case handler.processingCertificate == nil:
		return nil, errors.New("merchant processing not defined")
	}
	return handler, nil
}

func Decrypt(data []byte) (*ApplePayToken, error) {
	if defHandler == nil {
		return nil, fmt.Errorf("default apple handler not defined")
	}
	return defHandler.Decrypt(data)
}

func MerchantCertificate(crt tls.Certificate) IOption {
	return func(h *applePayHandler) error {
		if err := h.prepareCertificate(&crt); err != nil {
			return errors.New("invalid merchant certificate: " + err.Error())
		}
		if _, ok := crt.PrivateKey.(*rsa.PrivateKey); !ok {
			return errors.New("merchant key should be RSA")
		}
		h.merchantCertificate = &crt
		return nil
	}
}

func MerchantCertificateLocation(path string) IOption {
	return func(h *applePayHandler) error {
		c, err := paytokens.LoadPemCertificate(path)
		if err != nil {
			return errors.New("file read: " + err.Error())
		}
		h.merchantCertificate = c
		return nil
	}
}

func ProcessingCertificate(crt tls.Certificate) IOption {
	return func(h *applePayHandler) error {
		if err := h.prepareCertificate(&crt); err != nil {
			return errors.New("invalid processing certificate: " + err.Error())
		}
		if _, ok := crt.PrivateKey.(*ecdsa.PrivateKey); !ok {
			return errors.New("processing key should be ECDSA")
		}
		h.processingCertificate = &crt
		return nil
	}
}

func ProcessingCertificateLocation(path string) IOption {
	return func(h *applePayHandler) error {
		c, err := paytokens.LoadPemCertificate(path)
		if err != nil {
			return errors.New("file read: " + err.Error())
		}
		h.processingCertificate = c
		return nil
	}
}

func ParseApplePaySessionURL(str string) (*ApplePaySessionURL, error) {
	v, err := url.Parse(str)
	if err != nil {
		return nil, fmt.Errorf("error parsing the URL : " + str)
	}
	url := &ApplePaySessionURL{url: *v}
	if err := url.Validate(); err != nil {
		return nil, err
	}
	return url, nil
}
