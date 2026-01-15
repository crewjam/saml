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

	// Check if key is a concrete private key type that jwt library can handle directly.
	// For crypto.Signer implementations (KMS/HSM), use custom signing.
	switch c.Key.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
		return token.SignedString(c.Key)
	default:
		return signJWTWithCryptoSigner(token, c.Key, c.SigningMethod)
	}
}

// Decode parses the serialized session that may have been returned by Encode
// and returns a Session.
func (c JWTSessionCodec) Decode(signed string) (Session, error) {
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

// signJWTWithCryptoSigner signs a JWT token using the crypto.Signer interface.
// This allows KMS/HSM keys that implement crypto.Signer to sign JWTs.
func signJWTWithCryptoSigner(token *jwt.Token, signer crypto.Signer, method jwt.SigningMethod) (string, error) {
	// Get the signing string (header.payload)
	signingString, err := token.SigningString()
	if err != nil {
		return "", err
	}

	// Determine hash algorithm based on signing method
	var hashFunc crypto.Hash
	switch method.Alg() {
	case "RS256", "ES256", "PS256":
		hashFunc = crypto.SHA256
	case "RS384", "ES384", "PS384":
		hashFunc = crypto.SHA384
	case "RS512", "ES512", "PS512":
		hashFunc = crypto.SHA512
	default:
		hashFunc = crypto.SHA256
	}

	// Hash the signing string
	hasher := hashFunc.New()
	hasher.Write([]byte(signingString))
	digest := hasher.Sum(nil)

	// Sign using crypto.Signer
	sig, err := signer.Sign(rand.Reader, digest, hashFunc)
	if err != nil {
		return "", fmt.Errorf("signing with crypto.Signer: %w", err)
	}

	// For ECDSA, the signature from crypto.Signer is ASN.1 DER encoded,
	// but JWT expects raw R||S format
	if _, ok := signer.Public().(*ecdsa.PublicKey); ok {
		sig, err = convertECDSASignatureToJWT(sig, signer.Public().(*ecdsa.PublicKey))
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

	// Calculate key size in bytes
	keyBytes := (pubKey.Curve.Params().BitSize + 7) / 8

	// Create R||S format
	rBytes := sig.R.Bytes()
	sBytes := sig.S.Bytes()

	// Pad to key size
	result := make([]byte, 2*keyBytes)
	copy(result[keyBytes-len(rBytes):keyBytes], rBytes)
	copy(result[2*keyBytes-len(sBytes):], sBytes)

	return result, nil
}
