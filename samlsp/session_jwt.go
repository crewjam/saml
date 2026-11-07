package samlsp

import (
	"crypto"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/internal/signerutil"
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

	// MaxAge is how long an issued session token is valid. It should match
	// the MaxAge of the CookieSessionProvider that stores the token.
	MaxAge time.Duration
	Key    crypto.Signer
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
			setNameIDClaims(&claims, nameID)
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
				claims.Attributes[claimName] = append(claims.Attributes[claimName], attributeValueString(value))
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

// setNameIDClaims records the Format, NameQualifier and SPNameQualifier of
// nameID in claims, so that GetSAMLNameID can rebuild it. An omitted Format
// is recorded as the unspecified format, which it means (saml-core §8.3.1),
// so that a recorded Format marks a session made with these claims.
func setNameIDClaims(claims *JWTSessionClaims, nameID *saml.NameID) {
	if nameID.Value == "" {
		return
	}
	claims.NameIDFormat = nameID.Format
	if claims.NameIDFormat == "" {
		claims.NameIDFormat = string(saml.UnspecifiedNameIDFormat)
	}
	claims.NameIDNameQualifier = nameID.NameQualifier
	claims.NameIDSPNameQualifier = nameID.SPNameQualifier
}

// attributeValueString returns the string form of a SAML AttributeValue.
//
// Some attributes, such as eduPersonTargetedID, carry a <saml:NameID> element
// instead of text content. For those the NameID's value is returned; the
// AttributeValue's own character data is then only (possibly empty)
// whitespace around the child element.
func attributeValueString(value saml.AttributeValue) string {
	if value.NameID != nil {
		return value.NameID.Value
	}
	return value.Value
}

// Encode returns a serialized version of the Session.
//
// The provided session must be a JWTSessionClaims, otherwise this
// function will panic.
func (c JWTSessionCodec) Encode(s Session) (string, error) {
	claims := s.(JWTSessionClaims) // this will panic if you pass the wrong kind of session

	token := jwt.NewWithClaims(c.SigningMethod, claims)
	return signToken(token, c.Key)
}

// Decode parses the serialized session that may have been returned by Encode
// and returns a Session.
func (c JWTSessionCodec) Decode(signed string) (Session, error) {
	if signerutil.IsNil(c.Key) {
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

	// NameIDFormat, NameIDNameQualifier and NameIDSPNameQualifier are the
	// Format, NameQualifier and SPNameQualifier of the NameID of the
	// assertion the session was made from; its value is the JWT subject.
	// Together they let GetSAMLNameID rebuild that NameID, for example to
	// query the IdP's attribute authority (see Middleware.QueryAttributes).
	// Empty ones are omitted from the JWT. Sessions issued before these
	// claims existed have none of them.
	NameIDFormat          string `json:"saml-nameid-format,omitempty"`
	NameIDNameQualifier   string `json:"saml-nameid-nq,omitempty"`
	NameIDSPNameQualifier string `json:"saml-nameid-spnq,omitempty"`
}

var _ Session = JWTSessionClaims{}

// GetSAMLNameID implements SessionWithSAMLNameID. It returns the NameID of
// the assertion the session was made from, with its Format and qualifiers.
// It returns false if the session does not record the NameID's Format,
// because it was issued before JWTSessionCodec recorded it, or has no
// subject.
func (c JWTSessionClaims) GetSAMLNameID() (saml.NameID, bool) {
	if c.Subject == "" || c.NameIDFormat == "" {
		return saml.NameID{}, false
	}
	return saml.NameID{
		Format:          c.NameIDFormat,
		NameQualifier:   c.NameIDNameQualifier,
		SPNameQualifier: c.NameIDSPNameQualifier,
		Value:           c.Subject,
	}, true
}

var _ SessionWithSAMLNameID = JWTSessionClaims{}

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
