package paytokens

import (
	"encoding/base64"
	"encoding/json"
)

type Base64Encoded []byte

func (v Base64Encoded) String() string {
	return base64.StdEncoding.EncodeToString(v)
}

func (v *Base64Encoded) UnmarshalJSON(bytes []byte) error {
	str := ""
	if err := json.Unmarshal(bytes, &str); err != nil {
		return err
	}
	data, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return err
	}
	*v = data
	return nil
}
