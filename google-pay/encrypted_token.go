package gpay

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/nooize/paytokens"
	"os"
	"strings"
	"time"
)

type encryptedToken struct {
	Protocol        tokenProtocol           `json:"protocolVersion"`
	Signature       paytokens.Base64Encoded `json:"signature"`
	IntermediateKey intermediateKey         `json:"intermediateSigningKey"`
	SignedMessage   signedMessage           `json:"signedMessage"`
}

func (v *encryptedToken) verifyIntermediateSigningKey() error {
	data := constructSignedData(
		GoogleSenderId,
		string(v.Protocol),
		v.IntermediateKey.Key.Raw(),
	)
	for _, publicKey := range filterRootKeys(v.Protocol, !("TEST" == os.Getenv("MODE"))) {
		for _, signature := range v.IntermediateKey.Signatures {
			if err := verifySignature(&publicKey.Key.PublicKey, data, signature); err == nil {
				return nil
			}
		}
	}
	return fmt.Errorf("invalid signature for intermediate signing key")
}

func (v *encryptedToken) verifyMessageSignature(recipient string) error {
	publicKey, err := parsePublicKey(v.IntermediateKey.Key.Value)
	if err != nil {
		return err
	}
	data := constructSignedData(
		GoogleSenderId,
		recipient,
		string(v.Protocol),
		strings.ReplaceAll(v.SignedMessage.Raw(), "\\u003d", "="),
	)

	if err := verifySignature(publicKey, data, v.Signature); err != nil {
		return fmt.Errorf("invalid message signature: \n Exp: %s \n Error: %s",
			base64.StdEncoding.EncodeToString(v.Signature), err.Error())
	}

	return nil

}

type intermediateKey struct {
	Key        signedKey                 `json:"signedKey"`
	Signatures []paytokens.Base64Encoded `json:"signatures"`
}

func (v intermediateKey) IsExpired() bool {
	return v.Key.Expiration != nil && v.Key.Expiration.Before(time.Now())
}

type baseSignedKey struct {
	Value      paytokens.Base64Encoded `json:"keyValue"`
	Expiration *jsonTimestamp          `json:"keyExpiration"`
}

type signedKey struct {
	baseSignedKey
	raw string `json:"-"`
}

func (v *signedKey) Raw() string {
	return v.raw
}

func (v *signedKey) UnmarshalJSON(bytes []byte) (err error) {
	if err := json.Unmarshal(bytes, &v.raw); err != nil {
		return err
	}
	if err = json.Unmarshal([]byte(v.raw), &v.baseSignedKey); err != nil {
		return err
	}
	return nil
}

type baseSignedMessage struct {
	EncryptedMessage   paytokens.Base64Encoded
	EphemeralPublicKey paytokens.Base64Encoded `json:"ephemeralPublicKey"`
	Tag                paytokens.Base64Encoded `json:"tag"`
}

type signedMessage struct {
	baseSignedMessage
	raw string `json:"-"`
}

func (v *signedMessage) Raw() string {
	return v.raw
}

func (v *signedMessage) UnmarshalJSON(bytes []byte) (err error) {
	if err := json.Unmarshal(bytes, &v.raw); err != nil {
		return err
	}
	if err = json.Unmarshal([]byte(v.raw), &v.baseSignedMessage); err != nil {
		return err
	}
	return err
}
