package apay

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"github.com/pkg/errors"
	"io"
	"net/http"
)

// Session returns an opaque payload for setting up an Apple Pay session
func (m *applePayHandler) Session(url ApplePaySessionURL, domain string, name string) (sessionPayload []byte, err error) {
	// Verify that the session URL is Apple's
	if err := url.Validate(); err != nil {
		return nil, errors.Wrap(err, "invalid session request URL")
	}

	// Send a session request to Apple
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{
					*m.merchantCertificate,
				},
			},
		},
		Timeout: sessionRequestTimeout,
	}

	buf := bytes.NewBuffer(nil)
	_ = json.NewEncoder(buf).Encode(map[string]string{
		"merchantIdentifier": m.merchantId,
		"domainName":         domain,
		"displayName":        name,
	})
	res, err := httpClient.Post(url.String(), "application/json", buf)
	if err != nil {
		return nil, errors.Wrap(err, "error making the request")
	}
	defer res.Body.Close()

	// Return directly the result
	body, _ := io.ReadAll(res.Body)
	return body, nil
}
