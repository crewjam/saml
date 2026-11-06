package samlsp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/crewjam/saml"
)

const (
	defaultSessionMaxAge  = time.Hour
	claimNameSessionIndex = "SessionIndex"
)

// JWTSessionCodec implements SessionCoded to encode and decode Sessions from
// the corresponding JWT.
type JWTSessionCodec struct {
	SigningMethod jwt.SigningMethod
	Audience      string
	Issuer        string
	MaxAge        time.Duration
	Key           crypto.Signer
}

var _ SessionCodec = JWTSessionCodec{}

// New creates a Session from the SAML assertion.
//
// The returned Session is a JWTSessionClaims.
func (c JWTSessionCodec) New(assertion *saml.Assertion) (Session, error) {
	now := saml.TimeNow()
	claims := JWTSessionClaims{}
	claims.SAMLSession = true
	claims.Audience = jwt.ClaimStrings{c.Audience}
	claims.Issuer = c.Issuer
	claims.IssuedAt = jwt.NewNumericDate(now)
	claims.ExpiresAt = jwt.NewNumericDate(now.Add(c.MaxAge))
	claims.NotBefore = jwt.NewNumericDate(now)

	if sub := assertion.Subject; sub != nil {
		if nameID := sub.NameID; nameID != nil {
			claims.Subject = nameID.Value
		}
	}

	claims.Attributes = map[string][]string{}

	for _, attributeStatement := range assertion.AttributeStatements {
		for _, attr := range attributeStatement.Attributes {
			claimName := attr.FriendlyName
			if claimName == "" {
				claimName = attr.Name
			}
			for _, value := range attr.Values {
				claims.Attributes[claimName] = append(claims.Attributes[claimName], value.Value)
			}
		}
	}

	// add SessionIndex to claims Attributes
	for _, authnStatement := range assertion.AuthnStatements {
		claims.Attributes[claimNameSessionIndex] = append(claims.Attributes[claimNameSessionIndex],
			authnStatement.SessionIndex)
	}

	return claims, nil
}

// Encode returns a serialized version of the Session.
//
// The provided session must be a JWTSessionClaims, otherwise this
// function will panic.
func (c JWTSessionCodec) Encode(s Session) (string, error) {
	claims := s.(JWTSessionClaims) // this will panic if you pass the wrong kind of session

	token := jwt.NewWithClaims(c.SigningMethod, claims)
	return signToken(token, c.Key, c.SigningMethod)
}

// Decode parses the serialized session that may have been returned by Encode
// and returns a Session.
func (c JWTSessionCodec) Decode(signed string) (Session, error) {
	if saml.IsSignerNil(c.Key) {
		return nil, fmt.Errorf("decoding key is nil")
	}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{c.SigningMethod.Alg()}),
		jwt.WithTimeFunc(saml.TimeNow),
		jwt.WithAudience(c.Audience),
		jwt.WithIssuer(c.Issuer),
	)
	claims := JWTSessionClaims{}
	_, err := parser.ParseWithClaims(signed, &claims, func(*jwt.Token) (interface{}, error) {
		return c.Key.Public(), nil
	})
	// TODO(ross): check for errors due to bad time and return ErrNoSession
	if err != nil {
		return nil, err
	}
	if !claims.SAMLSession {
		return nil, errors.New("expected saml-session")
	}
	return claims, nil
}

// JWTSessionClaims represents the JWT claims in the encoded session
type JWTSessionClaims struct {
	jwt.RegisteredClaims
	Attributes  Attributes `json:"attr"`
	SAMLSession bool       `json:"saml-session"`
}

var _ Session = JWTSessionClaims{}

// GetAttributes implements SessionWithAttributes. It returns the SAMl attributes.
func (c JWTSessionClaims) GetAttributes() Attributes {
	return c.Attributes
}

// Attributes is a map of attributes provided in the SAML assertion
type Attributes map[string][]string

// Get returns the first attribute named `key` or an empty string if
// no such attributes is present.
func (a Attributes) Get(key string) string {
	if a == nil {
		return ""
	}
	v := a[key]
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

// signToken signs a JWT token using the provided crypto.Signer.
// For concrete key types (*rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey),
// it delegates directly to jwt.Token.SignedString. For other crypto.Signer
// implementations (e.g., KMS/HSM), it uses signJWTWithCryptoSigner.
func signToken(token *jwt.Token, signer crypto.Signer, method jwt.SigningMethod) (string, error) {
	if saml.IsSignerNil(signer) {
		return "", fmt.Errorf("signing key is nil")
	}

	switch signer.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
		return token.SignedString(signer)
	default:
		return signJWTWithCryptoSigner(token, signer, method)
	}
}

// signJWTWithCryptoSigner signs a JWT token using the crypto.Signer interface.
// This allows KMS/HSM keys that implement crypto.Signer to sign JWTs.
// Supports RSA (RS256/RS384/RS512), RSA-PSS (PS256/PS384/PS512),
// ECDSA (ES256/ES384/ES512), and EdDSA signing methods.
func signJWTWithCryptoSigner(token *jwt.Token, signer crypto.Signer, method jwt.SigningMethod) (string, error) {
	pubKey := signer.Public()

	// Get the signing string (header.payload)
	signingString, err := token.SigningString()
	if err != nil {
		return "", err
	}

	// EdDSA (Ed25519) requires signing the full unhashed message with crypto.Hash(0),
	// unlike RSA/ECDSA which sign a pre-computed digest.
	if method.Alg() == "EdDSA" {
		if _, ok := pubKey.(ed25519.PublicKey); !ok {
			return "", fmt.Errorf("EdDSA signing requires an Ed25519 key, got %T", pubKey)
		}
		sig, err := signer.Sign(rand.Reader, []byte(signingString), crypto.Hash(0))
		if err != nil {
			return "", fmt.Errorf("signing with crypto.Signer: %w", err)
		}
		return strings.Join([]string{signingString, base64.RawURLEncoding.EncodeToString(sig)}, "."), nil
	}

	// Validate that the signer's public key type matches the JWT algorithm.
	alg := method.Alg()
	switch {
	case strings.HasPrefix(alg, "RS") || strings.HasPrefix(alg, "PS"):
		if _, ok := pubKey.(*rsa.PublicKey); !ok {
			return "", fmt.Errorf("algorithm %s requires an RSA key, got %T", alg, pubKey)
		}
	case strings.HasPrefix(alg, "ES"):
		if _, ok := pubKey.(*ecdsa.PublicKey); !ok {
			return "", fmt.Errorf("algorithm %s requires an ECDSA key, got %T", alg, pubKey)
		}
	default:
		return "", fmt.Errorf("unsupported algorithm for crypto.Signer: %s", alg)
	}

	// Determine hash algorithm and signer options based on signing method.
	// RSA-PSS requires *rsa.PSSOptions; RSA PKCS1v15 and ECDSA use the hash directly.
	var hashFunc crypto.Hash
	var opts crypto.SignerOpts
	switch alg {
	case "RS256", "ES256":
		hashFunc = crypto.SHA256
		opts = crypto.SHA256
	case "RS384", "ES384":
		hashFunc = crypto.SHA384
		opts = crypto.SHA384
	case "RS512", "ES512":
		hashFunc = crypto.SHA512
		opts = crypto.SHA512
	case "PS256":
		hashFunc = crypto.SHA256
		opts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
	case "PS384":
		hashFunc = crypto.SHA384
		opts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA384}
	case "PS512":
		hashFunc = crypto.SHA512
		opts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA512}
	default:
		return "", fmt.Errorf("unsupported signing algorithm for crypto.Signer: %s", alg)
	}

	// Hash the signing string
	hasher := hashFunc.New()
	hasher.Write([]byte(signingString))
	digest := hasher.Sum(nil)

	// Sign using crypto.Signer
	sig, err := signer.Sign(rand.Reader, digest, opts)
	if err != nil {
		return "", fmt.Errorf("signing with crypto.Signer: %w", err)
	}

	// For ECDSA, the signature from crypto.Signer is ASN.1 DER encoded,
	// but JWT expects raw R||S format
	if ecPub, ok := pubKey.(*ecdsa.PublicKey); ok {
		sig, err = convertECDSASignatureToJWT(sig, ecPub)
		if err != nil {
			return "", err
		}
	}

	// Encode signature and return complete JWT
	return strings.Join([]string{signingString, base64.RawURLEncoding.EncodeToString(sig)}, "."), nil
}

// convertECDSASignatureToJWT converts ASN.1 DER encoded ECDSA signature to JWT format (R||S)
func convertECDSASignatureToJWT(derSig []byte, pubKey *ecdsa.PublicKey) ([]byte, error) {
	// Parse ASN.1 DER signature
	var sig struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(derSig, &sig); err != nil {
		return nil, fmt.Errorf("parsing ECDSA signature: %w", err)
	}

	if sig.R == nil || sig.S == nil {
		return nil, fmt.Errorf("invalid ECDSA signature: R or S is nil")
	}

	// Calculate key size in bytes
	keyBytes := (pubKey.Curve.Params().BitSize + 7) / 8

	// Create R||S format with zero-padding
	rBytes := sig.R.Bytes()
	sBytes := sig.S.Bytes()

	if len(rBytes) > keyBytes || len(sBytes) > keyBytes {
		return nil, fmt.Errorf("invalid ECDSA signature: component size (%d, %d) exceeds key size (%d)", len(rBytes), len(sBytes), keyBytes)
	}

	result := make([]byte, 2*keyBytes)
	copy(result[keyBytes-len(rBytes):keyBytes], rBytes)
	copy(result[2*keyBytes-len(sBytes):], sBytes)

	return result, nil
}
