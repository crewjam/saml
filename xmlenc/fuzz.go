package xmlenc

import (
	"crypto/rsa"

	"github.com/beevik/etree"
)

// Fuzz is the entry point for the retired go-fuzz harness. It parses data as
// XML and decrypts its root element with testKey, returning 1 if that
// succeeds and 0 otherwise.
//
// Deprecated: Fuzz exists only for go-fuzz, which this package no longer
// uses; the package is fuzzed with the native Go fuzzer (FuzzDecrypt, run
// with go test -fuzz=FuzzDecrypt ./xmlenc). Call Decrypt instead. Fuzz will
// be removed in a future major version.
func Fuzz(testKey *rsa.PrivateKey, data []byte) int {
	if decryptForFuzzing(testKey, data) != nil {
		return 0
	}
	return 1
}

// decryptForFuzzing parses data as XML and decrypts its root element with
// key. It is what the fuzz tests exercise.
func decryptForFuzzing(key *rsa.PrivateKey, data []byte) error {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(data); err != nil {
		return err
	}
	if doc.Root() == nil {
		return ErrCannotFindRequiredElement("root element")
	}
	_, err := Decrypt(key, doc.Root())
	return err
}
