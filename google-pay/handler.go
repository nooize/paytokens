package gpay

import (
	"crypto/ecdsa"
)

type googlePayHandler struct {
	merchantId         string
	merchantPrivateKey *ecdsa.PrivateKey
	liveMode           bool
}

func (d *googlePayHandler) MerchantId() string {
	return d.merchantId
}
