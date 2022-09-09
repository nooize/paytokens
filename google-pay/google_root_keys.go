package gpay

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
)

const (
	TestRootKeysUrl       = "https://payments.developers.google.com/paymentmethodtoken/test/keys.json"
	ProductionRootKeysUrl = "https://payments.developers.google.com/paymentmethodtoken/keys.json"
)

var (
	rootSigningKeys   = make([]*rootSigningKey, 0)
	rootSigningKeysMu = sync.RWMutex{}
)

type rootSigningKey struct {
	Protocol   tokenProtocol  `json:"protocolVersion"`
	Expiration *jsonTimestamp `json:"keyExpiration,omitempty"`
	Key        *rootPublicKey `json:"keyValue"`
	Production bool           `json:"-"`
}

type rootPublicKey struct {
	ecdsa.PublicKey
}

func (v *rootPublicKey) UnmarshalJSON(bytes []byte) error {
	str := ""
	if err := json.Unmarshal(bytes, &str); err != nil {
		return err
	}
	data, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return err
	}
	key, err := parsePublicKey(data)
	if err != nil {
		return err
	}
	*v = rootPublicKey{*key}
	return nil
}

func filterRootKeys(protocol tokenProtocol, live bool) []*rootSigningKey {
	out := make([]*rootSigningKey, 0)
	rootSigningKeysMu.RLock()
	for _, key := range rootSigningKeys {
		if key.Protocol == protocol && key.Production == live {
			out = append(out, key)
		}
	}
	rootSigningKeysMu.RUnlock()
	return out
}

func fetchRootSigningKeys() {
	rootSigningKeysMu.Lock()
	keys := fetchGoogleRootSigningKeys()
	keys = append(keys, fetchLocalRootSigningKeys()...)
	rootSigningKeys = keys
	rootSigningKeysMu.Unlock()
}

func fetchGoogleRootSigningKeys() (keys []*rootSigningKey) {
	keys = make([]*rootSigningKey, 0)

	if list, err := fetchKeysFromUrl(ProductionRootKeysUrl, true); err != nil {
		log.Printf("%v", err)
	} else {
		keys = append(keys, list...)
	}
	if list, err := fetchKeysFromUrl(TestRootKeysUrl, false); err != nil {
	} else {
		keys = append(keys, list...)
	}

	return keys
}

func fetchLocalRootSigningKeys() (keys []*rootSigningKey) {
	keys = make([]*rootSigningKey, 0)

	path := os.Getenv(EnvRootSignedKetsFile)
	if len(path) == 0 {
		return
	}
	_, err := os.Stat(path)
	switch {
	case err != nil && errors.Is(err, os.ErrNotExist):
		log.Printf("root keys file not exists : %v", path)
		return
	case err != nil:
		log.Printf("root keys file not exists : %v", path)
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("root keys file read: %v", err.Error())
		return
	}
	keys, err = parseRootSigningKeys(data, true)
	if err != nil {
		log.Printf("root keys file parse: %v", err.Error())
	}
	return
}

func fetchKeysFromUrl(url string, isProduction bool) ([]*rootSigningKey, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	return parseRootSigningKeys(data, isProduction)
}

func parseRootSigningKeys(data []byte, isProduction bool) ([]*rootSigningKey, error) {
	res := struct {
		Keys []*rootSigningKey `json:"keys"`
	}{}
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, err
	}
	for _, v := range res.Keys {
		v.Production = isProduction
	}
	return res.Keys, nil
}
