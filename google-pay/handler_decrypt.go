package gpay

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
)

func (d *googlePayHandler) Decrypt(input []byte) (*GooglePayToken, error) {
	req := new(encryptedToken)
	if err := json.Unmarshal(input, req); err != nil {
		return nil, err
	}
	/*
		if (!payload.has(PaymentMethodTokenConstants.JSON_ENCRYPTED_MESSAGE_KEY)
	*/
	switch {
	case req.Protocol != EcV2:
		return nil, fmt.Errorf("protocol %s not supported", req.Protocol)
	case len(req.Signature) == 0:
		return nil, errors.New("signature is empty")
	case len(req.IntermediateKey.Key.Value) == 0:
		return nil, errors.New("intermediate signed key value is empty")
	case len(req.IntermediateKey.Signatures) == 0:
		return nil, errors.New("intermediate key signatures is empty")
	case len(req.SignedMessage.Tag) == 0:
		return nil, errors.New("signed message tag is empty")
	case len(req.SignedMessage.EphemeralPublicKey) == 0:
		return nil, errors.New("ephemeral public key is empty")
	}

	if err := req.verifyIntermediateSigningKey(); err != nil {
		return nil, err
	}

	if req.IntermediateKey.IsExpired() {
		return nil, errors.New("intermediate key is expired")
	}

	if err := req.verifyMessageSignature(d.merchantId); err != nil {
		//return nil, err
	}

	// derive to get :
	//  - symmetricKey ( last 32 byte of deriveKey )
	//  - mackey ( first 32 byte of deriveKey )
	deriveKey, err := d.computeDeriveKey(req.SignedMessage.EphemeralPublicKey)
	if err != nil {
		return nil, err
	}
	symmetricKey := deriveKey[:32]

	mac := hmac.New(sha256.New, deriveKey[32:])
	mac.Write([]byte(req.SignedMessage.Raw()))
	if hmac.Equal(req.SignedMessage.Tag, mac.Sum(nil)) {
		return nil, errors.New("encrypted message MAC is not valid MAC Tag ")
	}

	// decrypt message
	cip, err := aes.NewCipher(symmetricKey)
	if err != nil {
		return nil, err
	}
	decrypted := make([]byte, len(req.SignedMessage.EncryptedMessage))
	ctr := cipher.NewCTR(cip, make([]byte, aes.BlockSize))
	ctr.XORKeyStream(decrypted, req.SignedMessage.EncryptedMessage)

	token := new(GooglePayToken)
	if err := json.Unmarshal(decrypted, token); err != nil {
		return nil, err
	}
	if len(token.GatewayMerchantId) == 0 {
		token.GatewayMerchantId = d.merchantId
	}
	return token, nil
}

func (d *googlePayHandler) computeDeriveKey(ephemeralBytes []byte) ([]byte, error) {
	public, err := unmarshalPublicKey(ephemeralBytes)
	if err != nil {
		return nil, err
	}
	x, _ := public.Curve.ScalarMult(public.X, public.Y, d.merchantPrivateKey.D.Bytes())
	if x == nil {
		return nil, errors.New("merchant private key scalar multiplication resulted in infinity")
	}

	demKey, err := computeHKDF(
		append(ephemeralBytes, x.Bytes()...), // key
		make([]byte, 32),                     // empty salt
		[]byte(GoogleSenderId),
		64)
	if err != nil {
		return nil, err
	}
	return demKey, nil
}
