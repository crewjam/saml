package samlsp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/golang-jwt/jwt/v5"
	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml"
)

const (
	soapEnvelopeNS      = "http://schemas.xmlsoap.org/soap/envelope/"
	soapLogoutRequestID = "id-soap-logout-request"
)

// soapLogoutApp serves lt's middleware at /saml/ and an application page,
// protected by RequireAccount, at /app.
type soapLogoutApp struct {
	*httptest.Server
	lt     *logoutTest
	errors []error
}

func newSOAPLogoutApp(t *testing.T) *soapLogoutApp {
	t.Helper()
	lt := newLogoutTest(t, saml.HTTPPostBinding)
	app := &soapLogoutApp{lt: lt}
	lt.m.OnError = func(w http.ResponseWriter, _ *http.Request, err error) {
		app.errors = append(app.errors, err)
		http.Error(w, "forbidden", http.StatusForbidden)
	}
	mux := http.NewServeMux()
	mux.Handle("/saml/", lt.m)
	mux.Handle("/app", lt.m.RequireAccount(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello "+SessionFromContext(r.Context()).(SessionWithNameID).GetNameID())
	})))
	app.Server = httptest.NewServer(mux)
	t.Cleanup(app.Close)
	return app
}

// cookie returns a session cookie for nameID, issued at issuedAt, with the
// given SessionIndexes, as JWTSessionCodec makes it.
func (app *soapLogoutApp) cookie(t *testing.T, nameID string, issuedAt time.Time, sessionIndexes ...string) *http.Cookie {
	t.Helper()
	provider := app.lt.m.Session.(CookieSessionProvider)
	codec := provider.Codec.(JWTSessionCodec)
	assertion := &saml.Assertion{Subject: &saml.Subject{NameID: &saml.NameID{Value: nameID}}}
	for _, sessionIndex := range sessionIndexes {
		assertion.AuthnStatements = append(assertion.AuthnStatements, saml.AuthnStatement{SessionIndex: sessionIndex})
	}
	oldTimeNow := saml.TimeNow
	saml.TimeNow = func() time.Time { return issuedAt }
	session, err := codec.New(assertion)
	saml.TimeNow = oldTimeNow
	assert.NilError(t, err)
	value, err := codec.Encode(session)
	assert.NilError(t, err)
	return &http.Cookie{Name: provider.Name, Value: value, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}
}

// get requests /app with cookie and returns the status code.
func (app *soapLogoutApp) get(t *testing.T, cookie *http.Cookie) int {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, app.URL+"/app", nil)
	assert.NilError(t, err)
	req.AddCookie(cookie)
	client := app.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	assert.NilError(t, err)
	defer func() { assert.Check(t, resp.Body.Close()) }()
	return resp.StatusCode
}

// post sends body to the SLO endpoint with the given Content-Type, as the
// IdP does with the SOAP binding, and returns the response.
func (app *soapLogoutApp) post(t *testing.T, contentType string, body []byte) (int, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, app.URL+app.lt.m.ServiceProvider.SloURL.Path, bytes.NewReader(body))
	assert.NilError(t, err)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("SOAPAction", "http://www.oasis-open.org/committees/security")
	resp, err := app.Client().Do(req)
	assert.NilError(t, err)
	defer func() { assert.Check(t, resp.Body.Close()) }()
	respBody, err := io.ReadAll(resp.Body)
	assert.NilError(t, err)
	return resp.StatusCode, respBody
}

// soapLogoutRequest returns a LogoutRequest from the IdP for nameID with the
// given SessionIndexes.
func (app *soapLogoutApp) soapLogoutRequest(nameID string, sessionIndexes ...string) *saml.LogoutRequest {
	req := app.lt.logoutRequest()
	req.ID = soapLogoutRequestID
	req.Destination = ""
	req.NameID = &saml.NameID{Value: nameID}
	saml.WithSessionIndexes(sessionIndexes...)(req)
	return req
}

// soapEnvelope returns el signed with key and cert (with signatureMethod)
// and wrapped in a SOAP envelope, or not signed if key is nil.
func soapEnvelope(t *testing.T, el *etree.Element, key *rsa.PrivateKey, cert *x509.Certificate, signatureMethod string) []byte {
	t.Helper()
	if key != nil {
		ctx, err := dsig.NewSigningContext(key, [][]byte{cert.Raw})
		assert.NilError(t, err)
		ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
		assert.NilError(t, ctx.SetSignatureMethod(signatureMethod))
		el, err = ctx.SignEnveloped(el)
		assert.NilError(t, err)
	}
	envelope := etree.NewElement("soapenv:Envelope")
	envelope.CreateAttr("xmlns:soapenv", soapEnvelopeNS)
	envelope.CreateElement("soapenv:Body").AddChild(el)
	doc := etree.NewDocument()
	doc.SetRoot(envelope)
	buf, err := doc.WriteToBytes()
	assert.NilError(t, err)
	return buf
}

// idpSOAP returns req signed by the IdP in a SOAP envelope.
func (app *soapLogoutApp) idpSOAP(t *testing.T, req *saml.LogoutRequest) []byte {
	t.Helper()
	return soapEnvelope(t, req.Element(), app.lt.idpKey, app.lt.idpCert, dsig.RSASHA256SignatureMethod)
}

// logoutResponseStatus checks that body is a SOAP envelope holding a
// LogoutResponse to the request of soapLogoutRequest, signed by the SP, and
// returns its status.
func (app *soapLogoutApp) logoutResponseStatus(t *testing.T, body []byte) string {
	t.Helper()
	doc := etree.NewDocument()
	assert.NilError(t, doc.ReadFromBytes(body))
	assert.Assert(t, doc.Root() != nil, "not XML: %s", body)
	assert.Check(t, is.Equal(doc.Root().NamespaceURI(), soapEnvelopeNS))
	responseEl := doc.FindElement("/Envelope/Body/LogoutResponse")
	assert.Assert(t, responseEl != nil, string(body))

	validationContext := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{app.lt.m.ServiceProvider.Certificate},
	})
	validationContext.Clock = dsig.NewFakeClockAt(logoutTestNow)
	_, err := validationContext.Validate(responseEl)
	assert.NilError(t, err, "the LogoutResponse is not signed by the SP")

	assert.Check(t, is.Equal(responseEl.SelectAttrValue("InResponseTo", ""), soapLogoutRequestID))
	statusCode := responseEl.FindElement("./Status/StatusCode")
	assert.Assert(t, statusCode != nil)
	return statusCode.SelectAttrValue("Value", "")
}

// A LogoutRequest from the IdP over SOAP for one SessionIndex ends that
// session: the next request with its cookie has no session. The user's other
// sessions, and other users' sessions, are not affected.
func TestServeSLOSOAPLogoutRequestEndsSession(t *testing.T) {
	app := newSOAPLogoutApp(t)
	alice1 := app.cookie(t, "alice@example.com", logoutTestNow, "index-1")
	alice2 := app.cookie(t, "alice@example.com", logoutTestNow, "index-2")
	bob := app.cookie(t, "bob@example.com", logoutTestNow, "index-1")
	for _, c := range []*http.Cookie{alice1, alice2, bob} {
		assert.Check(t, is.Equal(app.get(t, c), http.StatusOK))
	}

	status, body := app.post(t, "text/xml; charset=utf-8", app.idpSOAP(t, app.soapLogoutRequest("alice@example.com", "index-1")))
	assert.Check(t, is.Equal(status, http.StatusOK))
	assert.Check(t, is.Equal(app.logoutResponseStatus(t, body), saml.StatusSuccess))
	assert.Check(t, is.Len(app.errors, 0))

	// The revoked session is refused, and the user is sent to log in again.
	assert.Check(t, is.Equal(app.get(t, alice1), http.StatusFound))
	assert.Check(t, is.Equal(app.get(t, alice2), http.StatusOK))
	assert.Check(t, is.Equal(app.get(t, bob), http.StatusOK))

	session, err := app.lt.m.Session.GetSession(requestWithCookie(alice1))
	assert.Check(t, is.Nil(session))
	assert.Check(t, is.ErrorIs(err, ErrNoSession))
	assert.Check(t, is.ErrorIs(err, ErrSessionRevoked))
}

func requestWithCookie(c *http.Cookie) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "https://sp.example.com/app", nil)
	r.AddCookie(c)
	return r
}

// A LogoutRequest without a SessionIndex ends every session of its NameID
// issued before it (saml-core §3.7.1), but not a later login.
func TestServeSLOSOAPLogoutRequestWithoutSessionIndex(t *testing.T) {
	app := newSOAPLogoutApp(t)
	alice1 := app.cookie(t, "alice@example.com", logoutTestNow.Add(-10*time.Minute), "index-1")
	alice2 := app.cookie(t, "alice@example.com", logoutTestNow, "index-2")
	aliceNoIndex := app.cookie(t, "alice@example.com", logoutTestNow)
	bob := app.cookie(t, "bob@example.com", logoutTestNow, "index-1")

	status, body := app.post(t, "text/xml", app.idpSOAP(t, app.soapLogoutRequest("alice@example.com")))
	assert.Check(t, is.Equal(status, http.StatusOK))
	assert.Check(t, is.Equal(app.logoutResponseStatus(t, body), saml.StatusSuccess))

	for _, c := range []*http.Cookie{alice1, alice2, aliceNoIndex} {
		assert.Check(t, is.Equal(app.get(t, c), http.StatusFound))
	}
	assert.Check(t, is.Equal(app.get(t, bob), http.StatusOK))

	// Alice logs in again a second later; the new session is accepted.
	later := logoutTestNow.Add(time.Second)
	saml.TimeNow = func() time.Time { return later }
	assert.Check(t, is.Equal(app.get(t, app.cookie(t, "alice@example.com", later, "index-3")), http.StatusOK))
	assert.Check(t, is.Equal(app.get(t, alice2), http.StatusFound))
}

// A session that has no SessionIndex cannot be told apart from the one a
// LogoutRequest names, so it is ended too.
func TestServeSLOSOAPLogoutRequestSessionWithoutIndex(t *testing.T) {
	app := newSOAPLogoutApp(t)
	aliceNoIndex := app.cookie(t, "alice@example.com", logoutTestNow)
	aliceOther := app.cookie(t, "alice@example.com", logoutTestNow, "index-2")
	status, _ := app.post(t, "text/xml", app.idpSOAP(t, app.soapLogoutRequest("alice@example.com", "index-1")))
	assert.Check(t, is.Equal(status, http.StatusOK))
	assert.Check(t, is.Equal(app.get(t, aliceNoIndex), http.StatusFound))
	assert.Check(t, is.Equal(app.get(t, aliceOther), http.StatusOK))
}

// A client cannot get a revoked session back by changing its cookie: the
// claims that identify the session are covered by the JWT signature.
func TestServeSLOSOAPLogoutRequestCookieTampering(t *testing.T) {
	app := newSOAPLogoutApp(t)
	alice := app.cookie(t, "alice@example.com", logoutTestNow, "index-1")
	status, _ := app.post(t, "text/xml", app.idpSOAP(t, app.soapLogoutRequest("alice@example.com", "index-1")))
	assert.Check(t, is.Equal(status, http.StatusOK))

	// Move the issue time after the logout, keeping the signature.
	parts := strings.Split(alice.Value, ".")
	assert.Assert(t, is.Len(parts, 3))
	claims := jwtPayload(t, alice.Value)
	claims["iat"] = logoutTestNow.Add(time.Minute).Unix()
	claims["attr"] = map[string]interface{}{"SessionIndex": []string{"index-9"}}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(claims))
	unsigned, err := token.SigningString()
	assert.NilError(t, err)
	tampered := *alice
	tampered.Value = unsigned + "." + parts[2]
	assert.Check(t, is.Equal(app.get(t, &tampered), http.StatusFound))
	_, err = app.lt.m.Session.GetSession(requestWithCookie(&tampered))
	assert.Check(t, is.ErrorIs(err, ErrNoSession))
	assert.Check(t, !errors.Is(err, ErrSessionRevoked))
}

func soapLogoutTestKeyPair(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NilError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "evil.example.com"},
		NotBefore:    logoutTestNow.Add(-time.Hour),
		NotAfter:     logoutTestNow.Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	assert.NilError(t, err)
	cert, err := x509.ParseCertificate(der)
	assert.NilError(t, err)
	return key, cert
}

// Invalid SOAP LogoutRequests are answered with a SOAP Fault, passed to
// OnError, and end no session.
func TestServeSLOSOAPLogoutRequestRejects(t *testing.T) {
	evilKey, evilCert := soapLogoutTestKeyPair(t)
	for _, tc := range []struct {
		name    string
		body    func(t *testing.T, app *soapLogoutApp) []byte
		setup   func(t *testing.T, app *soapLogoutApp)
		wantErr error
	}{
		{name: "unsigned", body: func(t *testing.T, app *soapLogoutApp) []byte {
			return soapEnvelope(t, app.soapLogoutRequest("alice@example.com").Element(), nil, nil, "")
		}, wantErr: saml.ErrInvalidSignature},
		{name: "signed by someone else", body: func(t *testing.T, app *soapLogoutApp) []byte {
			return soapEnvelope(t, app.soapLogoutRequest("alice@example.com").Element(), evilKey, evilCert, dsig.RSASHA256SignatureMethod)
		}, wantErr: saml.ErrInvalidSignature},
		{name: "wrong issuer", body: func(t *testing.T, app *soapLogoutApp) []byte {
			req := app.soapLogoutRequest("alice@example.com")
			req.Issuer.Value = "https://evil.example.com/"
			return app.idpSOAP(t, req)
		}, wantErr: saml.ErrIssuerMismatch},
		{name: "SHA-1 with RejectSHA1Signatures", body: func(t *testing.T, app *soapLogoutApp) []byte {
			return soapEnvelope(t, app.soapLogoutRequest("alice@example.com").Element(), app.lt.idpKey, app.lt.idpCert, dsig.RSASHA1SignatureMethod)
		}, setup: func(_ *testing.T, app *soapLogoutApp) {
			app.lt.m.ServiceProvider.RejectSHA1Signatures = true
		}, wantErr: saml.ErrUnsupported},
		{name: "oversized body", body: func(t *testing.T, app *soapLogoutApp) []byte {
			return app.idpSOAP(t, app.soapLogoutRequest("alice@example.com"))
		}, setup: func(t *testing.T, _ *soapLogoutApp) {
			old := saml.MaxSOAPLogoutMessageSize
			saml.MaxSOAPLogoutMessageSize = 100
			t.Cleanup(func() { saml.MaxSOAPLogoutMessageSize = old })
		}, wantErr: saml.ErrMalformedMessage},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := newSOAPLogoutApp(t)
			if tc.setup != nil {
				tc.setup(t, app)
			}
			alice := app.cookie(t, "alice@example.com", logoutTestNow)

			status, body := app.post(t, "text/xml", tc.body(t, app))
			assert.Check(t, is.Equal(status, http.StatusInternalServerError))
			doc := etree.NewDocument()
			assert.NilError(t, doc.ReadFromBytes(body))
			assert.Assert(t, doc.Root() != nil, "not XML: %s", body)
			fault := doc.FindElement("/Envelope/Body/Fault")
			assert.Assert(t, fault != nil, string(body))
			assert.Check(t, is.Equal(fault.FindElement("faultcode").Text(), "soapenv:Client"))

			assert.Assert(t, is.Len(app.errors, 1))
			var ire *saml.InvalidResponseError
			assert.Assert(t, errors.As(app.errors[0], &ire))
			assert.Check(t, is.ErrorIs(ire.PrivateErr, tc.wantErr))

			assert.Check(t, is.Equal(app.get(t, alice), http.StatusOK))
		})
	}
}

// A replayed SOAP LogoutRequest is refused when a ReplayCache is set.
func TestServeSLOSOAPLogoutRequestReplay(t *testing.T) {
	app := newSOAPLogoutApp(t)
	app.lt.m.ServiceProvider.ReplayCache = NewMemoryReplayCache(10)
	body := app.idpSOAP(t, app.soapLogoutRequest("alice@example.com"))

	status, _ := app.post(t, "text/xml", body)
	assert.Check(t, is.Equal(status, http.StatusOK))
	status, _ = app.post(t, "text/xml", body)
	assert.Check(t, is.Equal(status, http.StatusInternalServerError))
	assert.Assert(t, is.Len(app.errors, 1))
	assert.Check(t, is.ErrorIs(app.errors[0], saml.ErrAssertionReplayed))
}

// A posted body that is not text/xml is not taken for a SOAP message.
func TestServeSLOSOAPNotSOAPContentType(t *testing.T) {
	app := newSOAPLogoutApp(t)
	alice := app.cookie(t, "alice@example.com", logoutTestNow)
	status, _ := app.post(t, "text/plain", app.idpSOAP(t, app.soapLogoutRequest("alice@example.com")))
	assert.Check(t, is.Equal(status, http.StatusForbidden))
	assert.Assert(t, is.Len(app.errors, 1))
	assert.Check(t, is.ErrorIs(app.errors[0], errSLOUnexpectedMessage))
	assert.Check(t, is.Equal(app.get(t, alice), http.StatusOK))
}

// When the session provider cannot end sessions on the server, the IdP is
// told so with the status Responder.
func TestServeSLOSOAPLogoutRequestResponder(t *testing.T) {
	for _, tc := range []struct {
		name    string
		setup   func(app *soapLogoutApp)
		wantErr error
	}{
		{"session provider without TerminateSessions", func(app *soapLogoutApp) {
			app.lt.m.Session = staticSessionProvider{}
		}, ErrSessionTerminationUnsupported},
		{"cookie provider without a store", func(app *soapLogoutApp) {
			provider := app.lt.m.Session.(CookieSessionProvider)
			provider.Revocations = nil
			app.lt.m.Session = provider
		}, ErrSessionTerminationUnsupported},
		{"full store", func(app *soapLogoutApp) {
			provider := app.lt.m.Session.(CookieSessionProvider)
			store := NewMemorySessionRevocationStore(1)
			assert.NilError(t, store.Revoke(context.Background(), "other", logoutTestNow, logoutTestNow.Add(time.Hour)))
			provider.Revocations = store
			app.lt.m.Session = provider
		}, ErrSessionRevocationStoreFull},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := newSOAPLogoutApp(t)
			tc.setup(app)
			status, body := app.post(t, "text/xml", app.idpSOAP(t, app.soapLogoutRequest("alice@example.com")))
			assert.Check(t, is.Equal(status, http.StatusOK))
			assert.Check(t, is.Equal(app.logoutResponseStatus(t, body), saml.StatusResponder))
			assert.Assert(t, is.Len(app.errors, 1))
			assert.Check(t, is.ErrorIs(app.errors[0], errSOAPLogoutNotTerminated))
			assert.Check(t, is.ErrorIs(app.errors[0], tc.wantErr))
		})
	}
}

// failingRevocationStore fails every call.
type failingRevocationStore struct{}

func (failingRevocationStore) Revoke(context.Context, string, time.Time, time.Time) error {
	return errors.New("store unavailable")
}

func (failingRevocationStore) RevokedAt(context.Context, string) (time.Time, error) {
	return time.Time{}, errors.New("store unavailable")
}

// If the store cannot be read, the session is refused with an error that
// is not ErrNoSession, so that the request fails rather than starting a
// login that would not help.
func TestCookieSessionProviderRevocationStoreError(t *testing.T) {
	app := newSOAPLogoutApp(t)
	alice := app.cookie(t, "alice@example.com", logoutTestNow)
	provider := app.lt.m.Session.(CookieSessionProvider)
	provider.Revocations = failingRevocationStore{}
	app.lt.m.Session = provider

	_, err := provider.GetSession(requestWithCookie(alice))
	assert.Check(t, is.ErrorContains(err, "store unavailable"))
	assert.Check(t, !errors.Is(err, ErrNoSession))
	assert.Check(t, is.Equal(app.get(t, alice), http.StatusForbidden))
}

func TestCookieSessionProviderTerminateSessions(t *testing.T) {
	lt := newLogoutTest(t)
	provider := lt.m.Session.(CookieSessionProvider)
	store := NewMemorySessionRevocationStore(10)
	provider.Revocations = store

	t.Run("BaseID", func(t *testing.T) {
		err := provider.TerminateSessions(context.Background(), &saml.LogoutRequest{})
		assert.Check(t, is.ErrorIs(err, saml.ErrUnsupported))
	})
	t.Run("records expire with the sessions", func(t *testing.T) {
		req := &saml.LogoutRequest{NameID: &saml.NameID{Value: "alice@example.com"}}
		assert.NilError(t, provider.TerminateSessions(context.Background(), req))
		got, err := store.RevokedAt(context.Background(), nameIDRevocationKey("alice@example.com"))
		assert.NilError(t, err)
		assert.Check(t, is.Equal(got, logoutTestNow))
		entry := store.entries[nameIDRevocationKey("alice@example.com")]
		assert.Check(t, is.Equal(entry.expiresAt, logoutTestNow.Add(defaultSessionMaxAge)))
	})
}

func TestMemorySessionRevocationStore(t *testing.T) {
	now := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	oldTimeNow := saml.TimeNow
	t.Cleanup(func() { saml.TimeNow = oldTimeNow })
	saml.TimeNow = func() time.Time { return now }
	ctx := context.Background()

	t.Run("records and expires", func(t *testing.T) {
		store := NewMemorySessionRevocationStore(10)
		got, err := store.RevokedAt(ctx, "a")
		assert.NilError(t, err)
		assert.Check(t, got.IsZero())

		assert.NilError(t, store.Revoke(ctx, "a", now, now.Add(time.Hour)))
		got, err = store.RevokedAt(ctx, "a")
		assert.NilError(t, err)
		assert.Check(t, is.Equal(got, now))

		saml.TimeNow = func() time.Time { return now.Add(time.Hour + time.Second) }
		t.Cleanup(func() { saml.TimeNow = func() time.Time { return now } })
		got, err = store.RevokedAt(ctx, "a")
		assert.NilError(t, err)
		assert.Check(t, got.IsZero())
		assert.Check(t, is.Len(store.entries, 0))
	})

	t.Run("keeps the later time and expiry", func(t *testing.T) {
		saml.TimeNow = func() time.Time { return now }
		store := NewMemorySessionRevocationStore(10)
		assert.NilError(t, store.Revoke(ctx, "a", now.Add(time.Minute), now.Add(2*time.Hour)))
		assert.NilError(t, store.Revoke(ctx, "a", now, now.Add(time.Hour)))
		assert.Check(t, is.Equal(store.entries["a"].revokedAt, now.Add(time.Minute)))
		assert.Check(t, is.Equal(store.entries["a"].expiresAt, now.Add(2*time.Hour)))
	})

	t.Run("size is capped", func(t *testing.T) {
		saml.TimeNow = func() time.Time { return now }
		store := NewMemorySessionRevocationStore(2)
		assert.NilError(t, store.Revoke(ctx, "a", now, now.Add(time.Minute)))
		assert.NilError(t, store.Revoke(ctx, "b", now, now.Add(time.Hour)))
		assert.Check(t, is.ErrorIs(store.Revoke(ctx, "c", now, now.Add(time.Hour)), ErrSessionRevocationStoreFull))
		// An existing key can still be updated when the store is full.
		assert.NilError(t, store.Revoke(ctx, "b", now.Add(time.Second), now.Add(time.Hour)))

		// Once "a" has expired, there is room again.
		saml.TimeNow = func() time.Time { return now.Add(2 * time.Minute) }
		assert.NilError(t, store.Revoke(ctx, "c", now, now.Add(time.Hour)))
		assert.Check(t, is.Len(store.entries, 2))
		_, ok := store.entries["a"]
		assert.Check(t, !ok)
	})

	t.Run("panics without room", func(t *testing.T) {
		defer func() { assert.Check(t, recover() != nil) }()
		NewMemorySessionRevocationStore(0)
	})
}

func TestDefaultSessionProviderRevocations(t *testing.T) {
	opts := Options{URL: mustParseURL("https://sp.example.com/")}
	provider := DefaultSessionProvider(opts)
	_, ok := provider.Revocations.(*MemorySessionRevocationStore)
	assert.Check(t, ok)

	opts.SessionRevocations = failingRevocationStore{}
	provider = DefaultSessionProvider(opts)
	assert.Check(t, is.Equal(provider.Revocations, SessionRevocationStore(failingRevocationStore{})))
}

func TestRevocationKeys(t *testing.T) {
	// Keys are distinct and short enough for any store.
	keys := map[string]bool{
		nameIDRevocationKey("alice"):                              true,
		nameIDRevocationKey("bob"):                                true,
		sessionIndexRevocationKey("alice", "1"):                   true,
		sessionIndexRevocationKey("alice1", ""):                   true,
		sessionIndexRevocationKey("alice", ""):                    true,
		sessionIndexRevocationKey("bob", "1"):                     true,
		sessionIndexRevocationKey(strings.Repeat("x", 1000), "y"): true,
	}
	assert.Check(t, is.Len(keys, 7))
	for key := range keys {
		assert.Check(t, len(key) <= 80, key)
	}
}

// The SP metadata advertises a SOAP SingleLogoutService only when asked to.
func TestSOAPSingleLogoutServiceMetadata(t *testing.T) {
	opts := Options{URL: mustParseURL("https://sp.example.com/")}
	sp := DefaultServiceProvider(opts)
	for _, endpoint := range sp.Metadata().SPSSODescriptors[0].SingleLogoutServices {
		assert.Check(t, endpoint.Binding != saml.SOAPBinding)
	}

	opts.LogoutBindings = []string{saml.HTTPPostBinding, saml.SOAPBinding}
	sp = DefaultServiceProvider(opts)
	assert.Check(t, is.DeepEqual(sp.Metadata().SPSSODescriptors[0].SingleLogoutServices, []saml.Endpoint{
		{Binding: saml.HTTPPostBinding, Location: "https://sp.example.com/saml/slo", ResponseLocation: "https://sp.example.com/saml/slo"},
		{Binding: saml.SOAPBinding, Location: "https://sp.example.com/saml/slo"},
	}))
}
