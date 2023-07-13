# google-pay / paytokens


Go package for handle Google Pay tokens.

## Usage

Install using :

`go get github.com/nooize/paytokens`.

Usage example :

```golang
 
import  "github.com/nooize/paytokens/google-pay"

...
	
  merchantId := "12345678901234567890"
  payToken := []byte("{ ... encrypted token ... }")
  
  decoder, err := gpay.New(
    merchantId,
    gpay.MerchantPrivateKeyLocation("private.pem"),
	gpay.TestMode(),
  )
  if err != nil {
	// handle error
  }
  
  decryptedToken, err := decoder.Decrypt(payToken)
  if err != nil {
    // handle error
  }

```

if you always decrypt with single merchant ID, you can use default decryptor.

To use default decryptor, simply define environment variable:
- GOOGLE_PAY_MERCHANT_ID
- GOOGLE_PAY_MERCHANT_PRIVATE_KEY


Usage with default decoder :

```golang

import  "github.com/nooize/paytokens"

...
	
  payToken := []byte("{ ... encrypted token ... }")
  
  decryptedToken, err := gpay.Decrypt(payToken)
  if err != nil {
   // handle error
  }

```

## Manage root signed certificates

GOOGLE_PAY_ROOT_SIGNED_KEYS_FILE


