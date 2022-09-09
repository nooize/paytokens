package apay

import (
	"strconv"
	"time"
)

// ApplePayToken is the decrypted form of Response.Token.PaymentData.Data
type ApplePayToken struct {

	// ApplicationPrimaryAccountNumber is the device-specific account number of the card that funds this
	// transaction
	ApplicationPrimaryAccountNumber string `json:"applicationPrimaryAccountNumber"`

	// expirationDate is the card expiration date in the format YYMMDD
	// use ExpirationTime function to access the time.Time value
	ExpirationDate expirationDate `json:"applicationExpirationDate"`

	// CurrencyCode is the ISO 4217 numeric currency code, as a string to preserve leading zeros
	CurrencyCode string `json:"currencyCode"`

	// TransactionAmount is the value of the transaction
	TransactionAmount uint `json:"transactionAmount"`

	// CardholderName is the name on the card
	CardholderName string `json:"cardholderName,omitempty"`

	// DeviceManufacturerIdentifier is a hex-encoded device manufacturer identifier
	DeviceManufacturerIdentifier string `json:"deviceManufacturerIdentifier"`

	// PaymentDataType is either 3DSecure or, if using Apple Pay in China, EMV
	PaymentDataType string `json:"paymentDataType"`

	// PaymentData contains detailed payment data
	PaymentData struct {
		// 3-D Secure fields

		// OnlinePaymentCryptogram is the 3-D Secure cryptogram
		OnlinePaymentCryptogram string `json:"onlinePaymentCryptogram,omitempty"`

		// ECIIndicator is the Electronic Commerce Indicator for the status of 3-D Secure
		ECIIndicator string `json:",omitempty"`

		// EMV fields

		// EMVData is the output from the Secure Element
		EMVData []byte `json:",omitempty"`

		// EncryptedPINData is the PIN encrypted with the bank's key
		EncryptedPINData string `json:",omitempty"`
	}
}

func (t *ApplePayToken) ExpirationTime() time.Time {
	return t.ExpirationDate.Time
}

func (t *ApplePayToken) HasCryptogram() bool {
	return len(t.PaymentData.OnlinePaymentCryptogram) > 0
}

func (t *ApplePayToken) Cryptogram() string {
	return t.PaymentData.OnlinePaymentCryptogram
}

func parseInt(v string) int {
	i, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0
	}
	return int(i)
}
