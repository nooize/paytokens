package openssl

/*
#include <openssl/x509v3.h>
#include <openssl/err.h>

// Replace macros for cgo
X509* sk_X509_value_func(STACK_OF(X509) *sk, int i) { return sk_X509_value(sk, i); }
void OpenSSL_add_all_algorithms_func() { OpenSSL_add_all_algorithms(); }
int sk_PKCS7_SIGNER_INFO_num_func(STACK_OF(PKCS7_SIGNER_INFO) *sk) { return sk_PKCS7_SIGNER_INFO_num(sk); }
PKCS7_SIGNER_INFO *sk_PKCS7_SIGNER_INFO_value_func(STACK_OF(PKCS7_SIGNER_INFO) *sk, int i) { return sk_PKCS7_SIGNER_INFO_value(sk, i); }
*/
import "C"

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
	"unsafe"
)

func parsePKCS7(data []byte) (*Pkcs7, error) {

	// Decode PKCS7 blob, certificate chain
	bio := newBIOBytes(data)
	defer bio.Free()
	nativeP7 := C.d2i_PKCS7_bio(bio.C(), nil)
	if nativeP7 == nil {
		return nil, errors.New("openssl error: could not decode PKCS7")
	}
	sign := (*C.PKCS7_SIGNED)(union(nativeP7.d))

	if sign == nil {
		C.PKCS7_free(nativeP7)
		return nil, errors.New("openssl error: error dereferencing d in PKCS7")
	}

	return &Pkcs7{p7: nativeP7}, nil
}

type Pkcs7 struct {
	p7 *C.PKCS7
}

func (o Pkcs7) signed() *C.PKCS7_SIGNED {
	return (*C.PKCS7_SIGNED)(union(o.p7.d))
}

func (o Pkcs7) verifyBio(bio *bio, i C.int) error {

	signed := (*C.PKCS7_SIGNED)(union(o.p7.d))
	if signed == nil {
		return errors.New("openssl error: error dereferencing d in PKCS7")
	}

	r := C.i2d_X509_bio(
		bio.C(),
		C.sk_X509_value_func(signed.cert, i),
	)
	if r != 1 {
		return fmt.Errorf("error encoding cert: %s", opensslError().Error())
	}
	return nil
}

// SigningTime returns the time of signing from a PKCS7 struct
func (o Pkcs7) SigningTime() (time.Time, error) {
	signerInfoList := C.PKCS7_get_signer_info(o.p7)
	if signerInfoList == nil {
		return time.Time{},
			errors.New("openssl error when extracting signer information")
	}

	// Find the right SIGNER_INFO field
	signerInfoListSize := int(C.sk_PKCS7_SIGNER_INFO_num_func(signerInfoList))
	var signingTime time.Time
	for i := 0; i < signerInfoListSize; i++ {
		si := C.sk_PKCS7_SIGNER_INFO_value_func(signerInfoList, C.int(i))
		if si == nil {
			continue
		}
		so := C.PKCS7_get_signed_attribute(si, C.NID_pkcs9_signingTime)
		if so == nil || so._type != C.V_ASN1_UTCTIME {
			continue
		}

		// Decode the signing time
		stBio := newBIO()
		r := C.ASN1_UTCTIME_print(stBio.C(), (*C.ASN1_UTCTIME)(union(so.value)))
		if r != 1 {
			stBio.Free()
			return time.Time{}, fmt.Errorf("time encoding error: %s", opensslError().Error())
		}
		pt, err := time.Parse("Jan _2 15:04:05 2006 MST", stBio.ReadAllString())
		if err != nil {
			stBio.Free()
			return time.Time{}, fmt.Errorf("time parsing error: %s", opensslError().Error())
		}
		signingTime = pt
		stBio.Free()
		break
	}
	if signingTime.IsZero() {
		return time.Time{}, errors.New("signing time not found")
	}

	return signingTime, nil
}

func (o Pkcs7) Free() {
	C.PKCS7_free(o.p7)
}

// union dereferences a union pointer so that its value can be used
// Don't do this at home!
func union(union [8]byte) unsafe.Pointer {
	dBuf := bytes.NewBuffer(union[:])
	var ptr uint64
	binary.Read(dBuf, binary.LittleEndian, &ptr)
	return unsafe.Pointer(uintptr(ptr))
}

// opensslError reads the errors from OpenSSL into a Go error
func opensslError() error {
	errOut := newBIO()
	defer errOut.Free()
	C.ERR_print_errors(errOut.C())
	return errors.New(errOut.ReadAllString())
}
