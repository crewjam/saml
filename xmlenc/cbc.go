package xmlenc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des" // nolint: gosec
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"github.com/beevik/etree"
)

// CBC implements Decrypter and Encrypter for block ciphers in CBC mode
type CBC struct {
	// Rand, if non-nil, is the source of the IV and the element ID that
	// Encrypt generates. If nil, crypto/rand is used (through the
	// deprecated package-level RandReader). RSA.Encrypt uses its own Rand
	// when this one is nil.
	Rand io.Reader

	keySize   int
	algorithm string
	cipher    func([]byte) (cipher.Block, error)
}

// KeySize returns the length of the key required.
func (e CBC) KeySize() int {
	return e.keySize
}

// Algorithm returns the name of the algorithm, as will be found
// in an xenc:EncryptionMethod element.
func (e CBC) Algorithm() string {
	return e.algorithm
}

// Encrypt encrypts plaintext with key, which should be a []byte of length KeySize().
// It returns an xenc:EncryptedData element.
func (e CBC) Encrypt(key interface{}, plaintext []byte, nonce []byte) (*etree.Element, error) {
	return e.encryptWithRand(nil, key, plaintext, nonce)
}

func (e CBC) encryptWithRand(rand io.Reader, key interface{}, plaintext []byte, _ []byte) (*etree.Element, error) {
	if e.Rand != nil {
		rand = e.Rand
	}
	rand = randOrDefault(rand)
	keyBuf, ok := key.([]byte)
	if !ok {
		return nil, ErrIncorrectKeyType("[]byte")
	}
	if len(keyBuf) != e.keySize {
		return nil, ErrIncorrectKeyLength(e.keySize)
	}

	block, err := e.cipher(keyBuf)
	if err != nil {
		return nil, err
	}

	encryptedDataEl := etree.NewElement("xenc:EncryptedData")
	encryptedDataEl.CreateAttr("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#")
	{
		randBuf := make([]byte, 16)
		if _, err := io.ReadFull(rand, randBuf); err != nil {
			return nil, err
		}
		encryptedDataEl.CreateAttr("Id", fmt.Sprintf("_%x", randBuf))
	}

	em := encryptedDataEl.CreateElement("xenc:EncryptionMethod")
	em.CreateAttr("Algorithm", e.algorithm)
	em.CreateAttr("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#")

	plaintext = appendPadding(plaintext, block.BlockSize())

	iv := make([]byte, block.BlockSize(), block.BlockSize()+len(plaintext))
	if _, err := io.ReadFull(rand, iv); err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(plaintext))
	mode.CryptBlocks(ciphertext, plaintext)
	ciphertext = append(iv, ciphertext...)

	cd := encryptedDataEl.CreateElement("xenc:CipherData")
	cd.CreateAttr("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#")
	cd.CreateElement("xenc:CipherValue").SetText(base64.StdEncoding.EncodeToString(ciphertext))
	return encryptedDataEl, nil
}

// Decrypt decrypts an encrypted element with key. If the ciphertext contains an
// EncryptedKey element, then the type of `key` is determined by the registered
// Decryptor for the EncryptedKey element. Otherwise, `key` must be a []byte of
// length KeySize().
func (e CBC) Decrypt(key interface{}, ciphertextEl *etree.Element) ([]byte, error) {
	// If the key is encrypted, decrypt it.
	if encryptedKeyEl := ciphertextEl.FindElement("./KeyInfo/EncryptedKey"); encryptedKeyEl != nil {
		var err error
		key, err = Decrypt(key, encryptedKeyEl)
		if err != nil {
			return nil, err
		}
	}

	keyBuf, ok := key.([]byte)
	if !ok {
		return nil, ErrIncorrectKeyType("[]byte")
	}
	if len(keyBuf) != e.KeySize() {
		return nil, ErrIncorrectKeyLength(e.KeySize())
	}

	block, err := e.cipher(keyBuf)
	if err != nil {
		return nil, err
	}

	ciphertext, err := getCiphertext(ciphertextEl)
	if err != nil {
		return nil, err
	}

	// The IV is prefixed, and at least one whole block must follow it.
	// CryptBlocks panics on input that is not a whole number of blocks.
	if len(ciphertext) < 2*block.BlockSize() {
		return nil, errors.New("ciphertext too short")
	}
	if len(ciphertext)%block.BlockSize() != 0 {
		return nil, errors.New("ciphertext is not a whole number of blocks")
	}

	iv := ciphertext[:block.BlockSize()]
	ciphertext = ciphertext[block.BlockSize():]

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext) // decrypt in place

	plaintext, err = stripPadding(plaintext, block.BlockSize())
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

var (
	// AES128CBC implements AES128-CBC symetric key mode for encryption and decryption
	AES128CBC BlockCipher = CBC{
		keySize:   16,
		algorithm: "http://www.w3.org/2001/04/xmlenc#aes128-cbc",
		cipher:    aes.NewCipher,
	}

	// AES192CBC implements AES192-CBC symetric key mode for encryption and decryption
	AES192CBC BlockCipher = CBC{
		keySize:   24,
		algorithm: "http://www.w3.org/2001/04/xmlenc#aes192-cbc",
		cipher:    aes.NewCipher,
	}

	// AES256CBC implements AES256-CBC symetric key mode for encryption and decryption
	AES256CBC BlockCipher = CBC{
		keySize:   32,
		algorithm: "http://www.w3.org/2001/04/xmlenc#aes256-cbc",
		cipher:    aes.NewCipher,
	}

	// TripleDES implements 3DES (DES-EDE3) in CBC mode for encryption and
	// decryption, with a 24 byte key as XML Encryption section 5.2.1 requires.
	// 3DES is a legacy cipher with a 64-bit block, so it is not registered as a
	// decrypter: a document naming tripledes-cbc gets ErrAlgorithmNotImplemented
	// unless the application opts in with RegisterDecrypter(TripleDES).
	TripleDES BlockCipher = CBC{
		keySize:   24,
		algorithm: "http://www.w3.org/2001/04/xmlenc#tripledes-cbc",
		cipher:    des.NewTripleDESCipher,
	}
)

func init() {
	RegisterDecrypter(AES128CBC)
	RegisterDecrypter(AES192CBC)
	RegisterDecrypter(AES256CBC)
}

func appendPadding(buf []byte, blockSize int) []byte {
	paddingBytes := blockSize - (len(buf) % blockSize)
	padding := make([]byte, paddingBytes)
	padding[len(padding)-1] = byte(paddingBytes) //nolint:gosec // paddingBytes <= blockSize, which is at most 16 for AES
	return append(buf, padding...)
}

// ErrDecryptionFailed is returned for a ciphertext whose decrypted bytes
// are not valid: in CBC mode, when the padding is not. It carries no detail,
// so that a caller that also rejects plaintext it cannot parse (as the
// saml package does) can report that with the same error, and a sender of
// modified ciphertexts cannot tell the two failures apart from the error.
//
// CBC without an integrity check remains malleable whatever the padding
// check: the XML Encryption attacks of Jager and Somorovsky (2011) need only
// learn whether a modified ciphertext decrypts to well-formed XML. Use
// AES-GCM where the sender supports it.
var ErrDecryptionFailed = errors.New("xmlenc: decryption failed")

// stripPadding removes XML Encryption padding (section 5.2): the last byte
// holds the number of padding bytes, between 1 and the block size, and the
// other padding bytes are arbitrary. They are not checked: unlike PKCS#7,
// XML Encryption lets them take any value, and common senders (Apache
// Santuario, .NET's EncryptedXml) use ISO 10126 padding, whose other bytes
// are random. Every failure returns ErrDecryptionFailed.
func stripPadding(buf []byte, blockSize int) ([]byte, error) {
	if len(buf) < 1 {
		return nil, ErrDecryptionFailed
	}
	paddingBytes := int(buf[len(buf)-1])
	if paddingBytes < 1 || paddingBytes > len(buf) || paddingBytes > blockSize {
		return nil, ErrDecryptionFailed
	}
	return buf[:len(buf)-paddingBytes], nil
}
