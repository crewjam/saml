// Package xmlenc is a partial implementation of the xmlenc standard
// as described in https://www.w3.org/TR/2002/REC-xmlenc-core-20021210/Overview.html.
// The purpose of this implementation is to support encrypted SAML assertions.
package xmlenc

import (
	"crypto/rand"
	"hash"
	"io"
	"sync"

	"github.com/beevik/etree"
)

// RandReader is the source of randomness used by an RSA, CBC or GCM whose
// Rand field is nil. By default it is Reader from crypto/rand.
//
// Deprecated: set the Rand field of RSA, CBC or GCM instead. Replacing this
// global changes the randomness for every user of the package in the
// process, so it cannot be done safely by concurrent tests.
var RandReader = rand.Reader

// randOrDefault returns r or, if it is nil, the deprecated package-level
// RandReader.
func randOrDefault(r io.Reader) io.Reader {
	if r != nil {
		return r
	}
	return RandReader
}

// randEncrypter is implemented by the block ciphers of this package, so that
// RSA.Encrypt can give them its own source of randomness.
type randEncrypter interface {
	// encryptWithRand is Encrypt, reading from the block cipher's own Rand
	// if it is set, and otherwise from rand.
	encryptWithRand(rand io.Reader, key interface{}, plaintext []byte, nonce []byte) (*etree.Element, error)
}

// Encrypter is an interface that encrypts things. Given a plaintext it returns an
// XML EncryptedData or EncryptedKey element. The required type of `key` varies
// depending on the implementation.
//
// nonce should be nil, so that the implementation generates any nonce or IV
// it needs from its source of randomness. Implementations that use a nonce (GCM) accept a
// caller-supplied one only for reproducible tests: see GCM.Encrypt.
type Encrypter interface {
	Encrypt(key interface{}, plaintext []byte, nonce []byte) (*etree.Element, error)
}

// Decrypter is an interface that decrypts things. The Decrypt() method returns the
// plaintext version of the EncryptedData or EncryptedKey element passed.
//
// You probably don't have to use this interface directly, instead you may call
// Decrypt() and it will examine the element to determine which Decrypter to use.
type Decrypter interface {
	Algorithm() string
	Decrypt(key interface{}, ciphertextEl *etree.Element) ([]byte, error)
}

// DigestMethod represents a digest method such as SHA1, etc.
type DigestMethod interface {
	Algorithm() string
	Hash() hash.Hash
}

// The registries are written by RegisterDecrypter, UnregisterDecrypter and
// RegisterDigestMethod, which an application may call after init, while
// Decrypt reads them, possibly from other goroutines.
var (
	registryMu    sync.RWMutex
	decrypters    = map[string]Decrypter{}
	digestMethods = map[string]DigestMethod{}
)

// RegisterDecrypter registers the specified decrypter so that it can be
// used with Decrypt(), replacing any decrypter registered for the same
// algorithm. It is safe to call concurrently with Decrypt.
func RegisterDecrypter(d Decrypter) {
	registryMu.Lock()
	defer registryMu.Unlock()
	decrypters[d.Algorithm()] = d
}

// UnregisterDecrypter removes the decrypter registered for algorithm, an
// EncryptionMethod URI, so that Decrypt returns ErrAlgorithmNotImplemented
// for documents that name it. It does nothing if no decrypter is registered
// for algorithm. It is safe to call concurrently with Decrypt.
//
// The algorithm Decrypt uses is the one the document names, so a sender can
// relabel AES-GCM ciphertext as AES-CBC of the same key size and have it
// decrypted in CBC mode, which has no integrity check. An application whose
// senders all use AES-GCM can refuse CBC altogether:
//
//	xmlenc.UnregisterDecrypter(xmlenc.AES128CBC.Algorithm())
//	xmlenc.UnregisterDecrypter(xmlenc.AES192CBC.Algorithm())
//	xmlenc.UnregisterDecrypter(xmlenc.AES256CBC.Algorithm())
func UnregisterDecrypter(algorithm string) {
	registryMu.Lock()
	defer registryMu.Unlock()
	delete(decrypters, algorithm)
}

// RegisterDigestMethod registers the specified digest method so that it can
// be used with Decrypt(). It is safe to call concurrently with Decrypt.
func RegisterDigestMethod(dm DigestMethod) {
	registryMu.Lock()
	defer registryMu.Unlock()
	digestMethods[dm.Algorithm()] = dm
}

// lookupDecrypter returns the decrypter registered for algorithm.
func lookupDecrypter(algorithm string) (Decrypter, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	d, ok := decrypters[algorithm]
	return d, ok
}

// lookupDigestMethod returns the digest method registered for algorithm.
func lookupDigestMethod(algorithm string) (DigestMethod, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	dm, ok := digestMethods[algorithm]
	return dm, ok
}

// BlockCipher implements a cipher with a fixed size key like AES or 3DES.
type BlockCipher interface {
	Encrypter
	Decrypter
	KeySize() int
}
