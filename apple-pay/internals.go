package apay

import (
	"encoding/asn1"
	"github.com/pkg/errors"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	sessionRequestTimeout       = 30 * time.Second
	envMerchantId               = "APPLE_PAY_MERCHANT_ID"
	envMerchantCertificateKey   = "APPLE_PAY_MERCHANT_CERTIFICATE_KEY"
	envProcessingCertificateKey = "APPLE_PAY_PROCESSING_CERTIFICATE_KEY"
	envRootCertificatePath      = "APPLE_PAY_ROOT_CERTIFICATE_PATH"
)

var (
	merchantIDHashOID   = mustParseASN1ObjectIdentifier("1.2.840.113635.100.6.32")
	leafCertificateOID  = mustParseASN1ObjectIdentifier("1.2.840.113635.100.6.29")
	interCertificateOID = mustParseASN1ObjectIdentifier("1.2.840.113635.100.6.2.14")

	defHandler IApplePayHandler
)

func init() {

	if err := func() error {
		merchantId := strings.TrimSpace(os.Getenv(envMerchantId))

		if len(merchantId) == 0 {
			return nil
		}

		handler, err := New(merchantId,
			MerchantCertificateLocation(os.Getenv(envMerchantCertificateKey)),
			ProcessingCertificateLocation(os.Getenv(envProcessingCertificateKey)),
		)
		if err == nil {
			defHandler = handler
		}

		return err
	}(); err != nil {
		log.Printf(err.Error())
	}

	fetchRootCertificate()

}

func mustParseASN1ObjectIdentifier(id string) asn1.ObjectIdentifier {
	oid, err := parseASN1ObjectIdentifier(id)
	if err != nil {
		panic(errors.Wrap(err, "error parsing the OID"))
	}
	return oid
}

// parseASN1ObjectIdentifier parses an ASN.1 object identifier string of the
// form x.x.x.x.x.x.x.x into a Go asn1.ObjectIdentifier
func parseASN1ObjectIdentifier(id string) (asn1.ObjectIdentifier, error) {
	idSplit := strings.Split(id, ".")
	oid := make([]int, len(idSplit))
	for i, str := range idSplit {
		r, err := strconv.Atoi(str)
		if err != nil {
			return nil, errors.Wrapf(err, "error parsing %s", str)
		}
		oid[i] = r
	}
	return oid, nil
}
