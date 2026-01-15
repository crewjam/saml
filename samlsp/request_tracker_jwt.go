package samlsp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/crewjam/saml"
)

// JWTTrackedRequestCodec encodes TrackedRequests as signed JWTs
type JWTTrackedRequestCodec struct {
	SigningMethod jwt.SigningMethod
	Audience      string
	Issuer        string
	MaxAge        time.Duration
	Key           crypto.Signer
}

var _ TrackedRequestCodec = JWTTrackedRequestCodec{}

// JWTTrackedRequestClaims represents the JWT claims for a tracked request.
type JWTTrackedRequestClaims struct {
	jwt.RegisteredClaims
	TrackedRequest
	SAMLAuthnRequest bool `json:"saml-authn-request"`
}

// Encode returns an encoded string representing the TrackedRequest.
func (s JWTTrackedRequestCodec) Encode(value TrackedRequest) (string, error) {
	now := saml.TimeNow()
	claims := JWTTrackedRequestClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Audience:  jwt.ClaimStrings{s.Audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(s.MaxAge)),
			IssuedAt:  jwt.NewNumericDate(now),
			Issuer:    s.Issuer,
			NotBefore: jwt.NewNumericDate(now), // TODO(ross): correct for clock skew
			Subject:   value.Index,
		},
		TrackedRequest:   value,
		SAMLAuthnRequest: true,
	}
	token := jwt.NewWithClaims(s.SigningMethod, claims)

	// Check if key is a concrete private key type that jwt library can handle directly.
	// For crypto.Signer implementations (KMS/HSM), use custom signing.
	switch s.Key.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
		return token.SignedString(s.Key)
	default:
		return signJWTWithCryptoSigner(token, s.Key, s.SigningMethod)
	}
}

// Decode returns a Tracked request from an encoded string.
func (s JWTTrackedRequestCodec) Decode(signed string) (*TrackedRequest, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{s.SigningMethod.Alg()}),
		jwt.WithTimeFunc(saml.TimeNow),
		jwt.WithAudience(s.Audience),
		jwt.WithIssuer(s.Issuer),
	)
	claims := JWTTrackedRequestClaims{}
	_, err := parser.ParseWithClaims(signed, &claims, func(*jwt.Token) (interface{}, error) {
		return s.Key.Public(), nil
	})
	if err != nil {
		return nil, err
	}
	if !claims.SAMLAuthnRequest {
		return nil, fmt.Errorf("expected saml-authn-request")
	}
	claims.Index = claims.Subject
	return &claims.TrackedRequest, nil
}
