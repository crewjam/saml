// Package signerutil contains helpers for working with crypto.Signer values.
package signerutil

import (
	"crypto"
	"reflect"
)

// IsNil reports whether key is nil, or is a non-nil interface holding a nil
// value such as (*rsa.PrivateKey)(nil) or a nil ed25519.PrivateKey. A plain
// == nil comparison misses the latter case, but calling Public() on it panics.
func IsNil(key crypto.Signer) bool {
	if key == nil {
		return true
	}
	v := reflect.ValueOf(key)
	switch v.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Map, reflect.Func, reflect.Chan, reflect.Interface:
		return v.IsNil()
	}
	return false
}
