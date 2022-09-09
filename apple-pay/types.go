package apay

import (
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type ApplePaySessionURL struct {
	url url.URL
}

func (u *ApplePaySessionURL) UnmarshalJSON(bytes []byte) error {
	cu, err := ParseApplePaySessionURL(strings.Trim(string(bytes), "\""))
	if err == nil {
		u.url = cu.url
	}
	return err
}

func (u *ApplePaySessionURL) String() string {
	return u.url.String()
}

func (u *ApplePaySessionURL) Validate() error {
	if u == nil {
		return errors.New("nil URL")
	}
	hostReg := regexp.MustCompile("^apple-pay-gateway(-.+)?.apple.com$")
	if !hostReg.MatchString(u.url.Host) {
		return errors.New("invalid host in apple pay url : " + u.url.Host)
	}
	if u.url.Scheme != "https" {
		return errors.New("only https protocol supported")
	}
	return nil
}

type tokenVersion string

func (v *tokenVersion) String() string {
	return string(*v)
}

func (p *tokenVersion) UnmarshalJSON(bytes []byte) error {
	str, _ := strconv.Unquote(string(bytes))
	switch tokenVersion(str) {
	case ecV1, rsaV1:
	default:
		return fmt.Errorf("version %v not supported", str)
	}
	*p = tokenVersion(str)
	return nil
}

type expirationDate struct {
	time.Time
}

func (v *expirationDate) UnmarshalJSON(bytes []byte) error {
	str := ""
	if err := json.Unmarshal(bytes, &str); err != nil {
		return err
	}
	if len(str) != 6 {
		return errors.New("exspect date in format YYMMDD")
	}
	*v = expirationDate{time.Date(
		2000+parseInt(str[:2]),
		time.Month(parseInt(str[2:4])),
		parseInt(str[4:]),
		0, 0, 0, 00, time.UTC)}
	return nil
}
