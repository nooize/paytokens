package gpay

import "time"

type GooglePayToken struct {
	MessageId           string        `json:"messageId"`
	MessageExpiration   string        `json:"messageExpiration"`
	PaymenMethod        PaymentMethod `json:"paymentMethod"`
	GatewayMerchantId   string        `json:"gatewayMerchantId,omitempty"`
	PaymenMethodDetails struct {
		AuthMethod      AuthMethod `json:"authMethod"`
		Pan             string     `json:"pan"`
		ExpirationMonth time.Month `json:"expirationMonth"`
		ExpirationYear  uint       `json:"expirationYear"`
		Cryptogram      string     `json:"cryptogram,omitempty"`
		EciIndicator    string     `json:"eciIndicator,omitempty"`
	} `json:"paymentMethodDetails"`
}

func (t *GooglePayToken) HasCryptogram() bool {
	return t.PaymenMethodDetails.AuthMethod == Cryptogram3ds && len(t.PaymenMethodDetails.Cryptogram) > 0
}
