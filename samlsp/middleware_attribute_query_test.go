package samlsp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/golang-jwt/jwt/v5"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml"
)

const (
	aqTestMailOID       = "urn:oid:0.9.2342.19200300.100.1.3"
	aqTestURINameFormat = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
)

// aqTestNameID is a NameID with every part JWTSessionCodec records.
var aqTestNameID = saml.NameID{
	Format:          string(saml.PersistentNameIDFormat),
	NameQualifier:   logoutTestIDPEntityID,
	SPNameQualifier: "https://sp.example.com/saml/metadata",
	Value:           "alice-persistent-id",
}

func aqTestAssertion(nameID saml.NameID) *saml.Assertion {
	return &saml.Assertion{Subject: &saml.Subject{NameID: &nameID}}
}

// jwtPayload returns the claims of the JWT token, as JSON object keys.
func jwtPayload(t *testing.T, token string) map[string]interface{} {
	t.Helper()
	parts := strings.Split(token, ".")
	assert.Assert(t, is.Len(parts, 3))
	buf, err := base64.RawURLEncoding.DecodeString(parts[1])
	assert.NilError(t, err)
	var claims map[string]interface{}
	assert.NilError(t, json.Unmarshal(buf, &claims))
	return claims
}

func TestJWTSessionNameIDClaimsRoundTrip(t *testing.T) {
	lt := newLogoutTest(t)
	codec := lt.m.Session.(CookieSessionProvider).Codec.(JWTSessionCodec)

	session, err := codec.New(aqTestAssertion(aqTestNameID))
	assert.NilError(t, err)
	token, err := codec.Encode(session)
	assert.NilError(t, err)

	payload := jwtPayload(t, token)
	assert.Check(t, is.Equal(payload["sub"], aqTestNameID.Value))
	assert.Check(t, is.Equal(payload["saml-nameid-format"], aqTestNameID.Format))
	assert.Check(t, is.Equal(payload["saml-nameid-nq"], aqTestNameID.NameQualifier))
	assert.Check(t, is.Equal(payload["saml-nameid-spnq"], aqTestNameID.SPNameQualifier))

	decoded, err := codec.Decode(token)
	assert.NilError(t, err)
	nameID, ok := decoded.(SessionWithSAMLNameID).GetSAMLNameID()
	assert.Check(t, ok)
	assert.Check(t, is.DeepEqual(nameID, aqTestNameID))
	assert.Check(t, is.Equal(decoded.(SessionWithNameID).GetNameID(), aqTestNameID.Value))
}

func TestJWTSessionNameIDClaimsOmitted(t *testing.T) {
	lt := newLogoutTest(t)
	codec := lt.m.Session.(CookieSessionProvider).Codec.(JWTSessionCodec)

	// Empty qualifiers are left out of the JWT; an omitted Format is the
	// unspecified format.
	session, err := codec.New(aqTestAssertion(saml.NameID{Value: "alice"}))
	assert.NilError(t, err)
	token, err := codec.Encode(session)
	assert.NilError(t, err)
	payload := jwtPayload(t, token)
	assert.Check(t, is.Equal(payload["saml-nameid-format"], string(saml.UnspecifiedNameIDFormat)))
	_, hasNQ := payload["saml-nameid-nq"]
	_, hasSPNQ := payload["saml-nameid-spnq"]
	assert.Check(t, !hasNQ && !hasSPNQ, "%v", payload)

	decoded, err := codec.Decode(token)
	assert.NilError(t, err)
	nameID, ok := decoded.(SessionWithSAMLNameID).GetSAMLNameID()
	assert.Check(t, ok)
	assert.Check(t, is.DeepEqual(nameID, saml.NameID{Format: string(saml.UnspecifiedNameIDFormat), Value: "alice"}))

	// An assertion without a NameID records none of the claims.
	session, err = codec.New(&saml.Assertion{})
	assert.NilError(t, err)
	token, err = codec.Encode(session)
	assert.NilError(t, err)
	_, hasFormat := jwtPayload(t, token)["saml-nameid-format"]
	assert.Check(t, !hasFormat)
}

// TestJWTSessionWithoutNameIDClaims decodes a session issued before
// JWTSessionCodec recorded the NameID's Format and qualifiers.
func TestJWTSessionWithoutNameIDClaims(t *testing.T) {
	lt := newLogoutTest(t)
	codec := lt.m.Session.(CookieSessionProvider).Codec.(JWTSessionCodec)
	token, err := signToken(jwt.NewWithClaims(codec.SigningMethod, jwt.MapClaims{
		"aud":          codec.Audience,
		"iss":          codec.Issuer,
		"sub":          "alice",
		"iat":          logoutTestNow.Unix(),
		"nbf":          logoutTestNow.Unix(),
		"exp":          logoutTestNow.Add(time.Hour).Unix(),
		"attr":         map[string][]string{"mail": {"alice@example.com"}},
		"saml-session": true,
	}), codec.Key)
	assert.NilError(t, err)

	decoded, err := codec.Decode(token)
	assert.NilError(t, err)
	claims := decoded.(JWTSessionClaims)
	assert.Check(t, is.Equal(claims.GetNameID(), "alice"))
	assert.Check(t, is.Equal(claims.GetAttributes().Get("mail"), "alice@example.com"))
	_, ok := claims.GetSAMLNameID()
	assert.Check(t, !ok)
}

// aqTestAuthority is an attribute authority that answers queries for
// aqTestNameID.
type aqTestAuthority struct {
	*httptest.Server
	queries []*saml.AttributeQuery
}

// newAQTestAuthority starts an attribute authority for lt's IdP and adds it
// to the IdP metadata.
func newAQTestAuthority(t *testing.T, lt *logoutTest) *aqTestAuthority {
	t.Helper()
	a := &aqTestAuthority{}
	a.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := readAttributeQuery(t, r)
		if query == nil || query.Subject == nil || query.Subject.NameID == nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		a.queries = append(a.queries, query)
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write(lt.attributeQueryResponse(t, query))
	}))
	t.Cleanup(a.Close)
	lt.m.ServiceProvider.IDPMetadata.AttributeAuthorityDescriptors = []saml.AttributeAuthorityDescriptor{{
		AttributeServices: []saml.Endpoint{{Binding: saml.SOAPBinding, Location: a.URL}},
	}}
	lt.m.ServiceProvider.HTTPClient = a.Client()
	return a
}

func readAttributeQuery(t *testing.T, r *http.Request) *saml.AttributeQuery {
	body, err := io.ReadAll(r.Body)
	assert.Check(t, err)
	doc := etree.NewDocument()
	assert.Check(t, doc.ReadFromBytes(body))
	queryEl := doc.FindElement("/Envelope/Body/AttributeQuery")
	if !assert.Check(t, queryEl != nil, "%s", body) {
		return nil
	}
	queryDoc := etree.NewDocument()
	queryDoc.SetRoot(queryEl.Copy())
	buf, err := queryDoc.WriteToBytes()
	assert.Check(t, err)
	query := &saml.AttributeQuery{}
	assert.Check(t, xml.Unmarshal(buf, query))
	return query
}

// attributeQueryResponse returns the SOAP response of the attribute
// authority to query: a Response signed by the IdP with an assertion about
// the queried NameID.
func (lt *logoutTest) attributeQueryResponse(t *testing.T, query *saml.AttributeQuery) []byte {
	audience := lt.m.ServiceProvider.EntityID
	if audience == "" {
		audience = lt.m.ServiceProvider.MetadataURL.String()
	}
	issuer := &saml.Issuer{Value: logoutTestIDPEntityID}
	nameID := *query.Subject.NameID
	response := &saml.Response{
		ID:           "id-attribute-response",
		InResponseTo: query.ID,
		Version:      "2.0",
		IssueInstant: logoutTestNow,
		Issuer:       issuer,
		Status:       saml.Status{StatusCode: saml.StatusCode{Value: saml.StatusSuccess}},
		Assertion: &saml.Assertion{
			ID:           "id-attribute-assertion",
			Version:      "2.0",
			IssueInstant: logoutTestNow,
			Issuer:       *issuer,
			Subject: &saml.Subject{
				NameID:               &nameID,
				SubjectConfirmations: []saml.SubjectConfirmation{{Method: "urn:oasis:names:tc:SAML:2.0:cm:sender-vouches"}},
			},
			Conditions: &saml.Conditions{
				NotBefore:            logoutTestNow.Add(-time.Minute),
				NotOnOrAfter:         logoutTestNow.Add(time.Minute),
				AudienceRestrictions: []saml.AudienceRestriction{{Audience: saml.Audience{Value: audience}}},
			},
			AttributeStatements: []saml.AttributeStatement{{Attributes: []saml.Attribute{{
				FriendlyName: "mail",
				Name:         aqTestMailOID,
				NameFormat:   aqTestURINameFormat,
				Values:       []saml.AttributeValue{{Type: "xs:string", Value: "alice@example.com"}},
			}}}},
		},
	}
	signed, err := base64.StdEncoding.DecodeString(lt.signedIDPMessage(t, response.Element()))
	assert.Check(t, err)
	return []byte(`<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body>` +
		strings.TrimPrefix(string(signed), `<?xml version="1.0" encoding="UTF-8"?>`) +
		`</soapenv:Body></soapenv:Envelope>`)
}

// loginCookie creates a session for an assertion about nameID, as ServeACS
// does, and returns its cookie.
func (lt *logoutTest) loginCookie(t *testing.T, nameID saml.NameID) *http.Cookie {
	t.Helper()
	resp := httptest.NewRecorder()
	err := lt.m.Session.CreateSession(resp, httptest.NewRequest(http.MethodPost, "https://sp.example.com/saml/acs", nil),
		aqTestAssertion(nameID))
	assert.NilError(t, err)
	name := lt.m.Session.(CookieSessionProvider).Name
	for _, c := range resp.Result().Cookies() {
		if c.Name == name && c.Value != "" {
			return c
		}
	}
	t.Fatalf("no session cookie: %v", resp.Header().Values("Set-Cookie"))
	return nil
}

func TestMiddlewareQueryAttributes(t *testing.T) {
	lt := newLogoutTest(t)
	authority := newAQTestAuthority(t, lt)
	cookie := lt.loginCookie(t, aqTestNameID)

	var result *saml.AttributeQueryResult
	var queryErr error
	handler := lt.m.RequireAccount(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		result, queryErr = lt.m.QueryAttributes(r, saml.Attribute{Name: aqTestMailOID, NameFormat: aqTestURINameFormat})
	}))
	req := httptest.NewRequest(http.MethodGet, "https://sp.example.com/profile", nil)
	req.AddCookie(cookie)
	handler.ServeHTTP(httptest.NewRecorder(), req)

	assert.NilError(t, queryErr)
	assert.Assert(t, is.Len(result.Attributes, 1))
	assert.Check(t, is.Equal(result.Attributes[0].Values[0].Value, "alice@example.com"))

	// The query names the user by the NameID of the login, Format and
	// qualifiers included.
	assert.Assert(t, is.Len(authority.queries, 1))
	assert.Check(t, is.DeepEqual(*authority.queries[0].Subject.NameID, aqTestNameID))
	assert.Check(t, is.Len(authority.queries[0].Attributes, 1))

	// Without RequireAccount, the session is read from the request.
	result, queryErr = lt.m.QueryAttributes(req)
	assert.NilError(t, queryErr)
	assert.Check(t, is.Len(result.Attributes, 1))
	assert.Check(t, is.Len(authority.queries, 2))
}

func TestMiddlewareQueryAttributesErrors(t *testing.T) {
	newRequest := func(cookies ...*http.Cookie) *http.Request {
		req := httptest.NewRequest(http.MethodGet, "https://sp.example.com/profile", nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		return req
	}

	t.Run("no session", func(t *testing.T) {
		lt := newLogoutTest(t)
		authority := newAQTestAuthority(t, lt)
		_, err := lt.m.QueryAttributes(newRequest())
		assert.Check(t, errors.Is(err, ErrNoSession), "%v", err)
		assert.Check(t, is.Len(authority.queries, 0))
	})
	t.Run("session issued without the NameID claims", func(t *testing.T) {
		lt := newLogoutTest(t)
		authority := newAQTestAuthority(t, lt)
		_, err := lt.m.QueryAttributes(newRequest(lt.sessionCookie(t, "")))
		assert.Check(t, errors.Is(err, ErrSessionNameIDUnknown), "%v", err)
		assert.Check(t, is.ErrorContains(err, "the user must log in again"))
		assert.Check(t, is.ErrorContains(err, "predates the NameID Format claim"))
		assert.Check(t, is.Len(authority.queries, 0))
	})
	t.Run("session that does not record the NameID", func(t *testing.T) {
		lt := newLogoutTest(t)
		authority := newAQTestAuthority(t, lt)
		lt.m.Session = staticSessionProvider{session: sessionWithoutNameID{}}
		_, err := lt.m.QueryAttributes(newRequest())
		assert.Check(t, errors.Is(err, ErrSessionNameIDUnknown), "%v", err)
		assert.Check(t, is.ErrorContains(err, "does not implement SessionWithSAMLNameID"))
		assert.Check(t, is.Len(authority.queries, 0))
	})
	t.Run("nil session", func(t *testing.T) {
		lt := newLogoutTest(t)
		lt.m.Session = staticSessionProvider{}
		_, err := lt.m.QueryAttributes(newRequest())
		assert.Check(t, errors.Is(err, ErrNoSession), "%v", err)
	})
	t.Run("no attribute authority", func(t *testing.T) {
		lt := newLogoutTest(t)
		_, err := lt.m.QueryAttributes(newRequest(lt.loginCookie(t, aqTestNameID)))
		assert.Check(t, errors.Is(err, saml.ErrNoAttributeService), "%v", err)
	})
	t.Run("request context is used", func(t *testing.T) {
		lt := newLogoutTest(t)
		authority := newAQTestAuthority(t, lt)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := lt.m.QueryAttributes(newRequest(lt.loginCookie(t, aqTestNameID)).WithContext(ctx))
		assert.Check(t, errors.Is(err, context.Canceled), "%v", err)
		assert.Check(t, is.Len(authority.queries, 0))
	})
}
