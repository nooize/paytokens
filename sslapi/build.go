//go:build !openssl_static
// +build !openssl_static

package sslapi

// #cgo linux windows freebsd openbsd solaris pkg-config: libssl libcrypto
// #cgo linux freebsd openbsd solaris CFLAGS: -Wno-deprecated-declarations
// #cgo darwin CFLAGS: -I/usr/local/opt/openssl@1.1/include -I/usr/local/opt/openssl/include -Wno-deprecated-declarations
// #cgo darwin LDFLAGS: -L/usr/local/opt/openssl@1.1/lib -L/usr/local/opt/openssl/lib -lssl -lcrypto
// #cgo windows CFLAGS: -DWIN32_LEAN_AND_MEAN
//#include <openssl/x509v3.h>
import "C"
