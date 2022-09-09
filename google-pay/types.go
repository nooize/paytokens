package gpay

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

type PaymentMethod string

func (m *PaymentMethod) String() string {
	return string(*m)
}

func (m *PaymentMethod) UnmarshalJSON(bytes []byte) error {
	str, _ := strconv.Unquote(string(bytes))
	switch PaymentMethod(str) {
	case Card:
	case TokenizedCard:
	default:
		return fmt.Errorf("payment method %v not supported", str)
	}
	*m = PaymentMethod(str)
	return nil
}

type AuthMethod string

func (m *AuthMethod) String() string {
	return string(*m)
}

func (m *AuthMethod) UnmarshalJSON(bytes []byte) error {
	str, _ := strconv.Unquote(string(bytes))
	switch AuthMethod(str) {
	case PanOnly:
	case Cryptogram3ds:
	default:
		return fmt.Errorf("token auth method %v not supported", str)
	}
	*m = AuthMethod(str)
	return nil
}

type tokenProtocol string

func (p *tokenProtocol) String() string {
	return string(*p)
}

func (p *tokenProtocol) UnmarshalJSON(bytes []byte) error {
	str, _ := strconv.Unquote(string(bytes))
	switch tokenProtocol(str) {
	case EcV1:
	case EcV2:
	case EcV2SigningOnly:
	default:
		return fmt.Errorf("protocol %v not supported", str)
	}
	*p = tokenProtocol(str)
	return nil
}

type jsonTimestamp struct {
	time.Time
}

func (v *jsonTimestamp) UnmarshalJSON(bytes []byte) error {
	str := ""
	if err := json.Unmarshal(bytes, &str); err != nil {
		return err
	}
	ts, err := strconv.ParseInt(str, 10, 64)
	if err != nil {
		return fmt.Errorf("%s is not unix time stamp", str)
	}
	if err != nil {
		return err
	}
	lt := time.Unix(ts/1000, 0)
	*v = jsonTimestamp{time.Date(lt.Year(), lt.Month(), lt.Day(), lt.Hour(), lt.Minute(), lt.Second(), 00, time.UTC)}
	return nil
}
