package samlsp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"

	"github.com/crewjam/saml"
)

func covSessionCodec(t *testing.T) JWTSessionCodec {
	t.Helper()
	return DefaultSessionCodec(Options{URL: mustParseURL("https://sp.example.com/"), Key: covRSAKey(t)})
}

func covTrackedRequestCodec(t *testing.T) JWTTrackedRequestCodec {
	t.Helper()
	return DefaultTrackedRequestCodec(Options{URL: mustParseURL("https://sp.example.com/"), Key: covRSAKey(t)})
}

// covSessionCodecErr is a SessionCodec whose New fails.
type covSessionCodecErr struct {
	JWTSessionCodec
}

func (covSessionCodecErr) New(*saml.Assertion) (Session, error) {
	return nil, errors.New("cov: new failed")
}

// covPlainSession is a Session that does not expose attributes.
type covPlainSession struct{}

// --- session.go ---

func TestCovAttributeFromContext(t *testing.T) {
	ctx := context.Background()
	assert.Check(t, is.Equal("", AttributeFromContext(ctx, "uid")))
	assert.Check(t, is.Equal("", AttributeFromContext(ContextWithSession(ctx, covPlainSession{}), "uid")))
	s := JWTSessionClaims{Attributes: Attributes{"uid": {"alice", "bob"}}}
	assert.Check(t, is.Equal("alice", AttributeFromContext(ContextWithSession(ctx, s), "uid")))
	assert.Check(t, is.Equal("", AttributeFromContext(ContextWithSession(ctx, s), "missing")))
}

// --- session_jwt.go ---

func TestCovJWTSessionCodecNew(t *testing.T) {
	codec := covSessionCodec(t)
	s, err := codec.New(&saml.Assertion{
		Subject: &saml.Subject{NameID: &saml.NameID{Value: "alice"}},
		AttributeStatements: []saml.AttributeStatement{{Attributes: []saml.Attribute{
			{Name: "urn:oid:0.9.2342.19200300.100.1.1", Values: []saml.AttributeValue{{Value: "alice"}}},
			{FriendlyName: "mail", Name: "urn:oid:0.9.2342.19200300.100.1.3", Values: []saml.AttributeValue{{Value: "a@example.com"}}},
		}}},
		AuthnStatements: []saml.AuthnStatement{{SessionIndex: "idx-1"}},
	})
	assert.Assert(t, err)
	claims := s.(JWTSessionClaims)
	assert.Check(t, is.Equal("alice", claims.Subject))
	assert.Check(t, is.Equal("alice", claims.Attributes.Get("urn:oid:0.9.2342.19200300.100.1.1")))
	assert.Check(t, is.Equal("a@example.com", claims.Attributes.Get("mail")))
	assert.Check(t, is.Equal("idx-1", claims.Attributes.Get(claimNameSessionIndex)))
	assert.Check(t, claims.SAMLSession)

	// Subject without NameID.
	s, err = codec.New(&saml.Assertion{Subject: &saml.Subject{}})
	assert.Assert(t, err)
	assert.Check(t, is.Equal("", s.(JWTSessionClaims).Subject))
}

func TestCovJWTSessionCodecEncodeError(t *testing.T) {
	codec := covSessionCodec(t)
	codec.Key = nil
	_, err := codec.Encode(JWTSessionClaims{})
	assert.Check(t, err != nil)
}

func TestCovJWTSessionCodecDecode(t *testing.T) {
	covSaveGlobals(t)
	base := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	saml.TimeNow = func() time.Time { return base }
	codec := covSessionCodec(t)
	session, err := codec.New(&saml.Assertion{})
	assert.Assert(t, err)
	valid, err := codec.Encode(session)
	assert.Assert(t, err)

	t.Run("valid", func(t *testing.T) {
		_, err := codec.Decode(valid)
		assert.Check(t, err)
	})

	t.Run("not a saml session", func(t *testing.T) {
		claims := session.(JWTSessionClaims)
		claims.SAMLSession = false
		token, err := codec.Encode(claims)
		assert.Assert(t, err)
		_, err = codec.Decode(token)
		assert.Check(t, is.Error(err, "expected saml-session"))
	})

	t.Run("tracked request token is not a session", func(t *testing.T) {
		token, err := covTrackedRequestCodec(t).Encode(TrackedRequest{Index: "abc", SAMLRequestID: "id-1", URI: "/"})
		assert.Assert(t, err)
		_, err = codec.Decode(token)
		assert.Check(t, is.Error(err, "expected saml-session"))
	})

	t.Run("wrong audience", func(t *testing.T) {
		other := codec
		other.Audience = "https://other.example.com/"
		_, err := other.Decode(valid)
		assert.Check(t, errors.Is(err, jwt.ErrTokenInvalidAudience))
	})

	t.Run("wrong issuer", func(t *testing.T) {
		other := codec
		other.Issuer = "https://other.example.com/"
		_, err := other.Decode(valid)
		assert.Check(t, errors.Is(err, jwt.ErrTokenInvalidIssuer))
	})

	t.Run("expired", func(t *testing.T) {
		saml.TimeNow = func() time.Time { return base.Add(2 * defaultSessionMaxAge) }
		defer func() { saml.TimeNow = func() time.Time { return base } }()
		_, err := codec.Decode(valid)
		assert.Check(t, errors.Is(err, jwt.ErrTokenExpired))
	})

	t.Run("not yet valid", func(t *testing.T) {
		saml.TimeNow = func() time.Time { return base.Add(-time.Hour) }
		defer func() { saml.TimeNow = func() time.Time { return base } }()
		_, err := codec.Decode(valid)
		assert.Check(t, errors.Is(err, jwt.ErrTokenNotValidYet))
	})

	t.Run("alg none rejected", func(t *testing.T) {
		token, err := jwt.NewWithClaims(jwt.SigningMethodNone, session.(JWTSessionClaims)).
			SignedString(jwt.UnsafeAllowNoneSignatureType)
		assert.Assert(t, err)
		_, err = codec.Decode(token)
		assert.Check(t, errors.Is(err, jwt.ErrTokenSignatureInvalid))
	})

	t.Run("hmac with public key rejected", func(t *testing.T) {
		token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, session.(JWTSessionClaims)).
			SignedString([]byte("secret"))
		assert.Assert(t, err)
		_, err = codec.Decode(token)
		assert.Check(t, errors.Is(err, jwt.ErrTokenSignatureInvalid))
	})
}

func TestCovAttributesGet(t *testing.T) {
	var nilAttrs Attributes
	assert.Check(t, is.Equal("", nilAttrs.Get("x")))
	assert.Check(t, is.Equal("", Attributes{"x": {}}.Get("x")))
	assert.Check(t, is.Equal("1", Attributes{"x": {"1", "2"}}.Get("x")))
}

// --- session_cookie.go ---

func covCookieSessionProvider(t *testing.T) CookieSessionProvider {
	t.Helper()
	return CookieSessionProvider{
		Name:     "token",
		Domain:   "sp.example.com:8443",
		HTTPOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   time.Hour,
		Codec:    covSessionCodec(t),
	}
}

func TestCovCookieSessionProviderCreateSession(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		p := covCookieSessionProvider(t)
		p.Path = "/app"
		rec := httptest.NewRecorder()
		assert.Assert(t, p.CreateSession(rec, httptest.NewRequest(http.MethodGet, "/", nil), &saml.Assertion{}))
		cookies := rec.Result().Cookies()
		assert.Assert(t, is.Len(cookies, 1))
		c := cookies[0]
		assert.Check(t, is.Equal("token", c.Name))
		assert.Check(t, is.Equal("sp.example.com", c.Domain))
		assert.Check(t, is.Equal("/app", c.Path))
		assert.Check(t, c.HttpOnly)
		assert.Check(t, c.Secure)
		assert.Check(t, is.Equal(http.SameSiteLaxMode, c.SameSite))
		assert.Check(t, is.Equal(3600, c.MaxAge))
	})

	t.Run("new error", func(t *testing.T) {
		p := covCookieSessionProvider(t)
		p.Codec = covSessionCodecErr{}
		err := p.CreateSession(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil), &saml.Assertion{})
		assert.Check(t, is.Error(err, "cov: new failed"))
	})

	t.Run("encode error", func(t *testing.T) {
		p := covCookieSessionProvider(t)
		codec := covSessionCodec(t)
		codec.Key = nil
		p.Codec = codec
		rec := httptest.NewRecorder()
		err := p.CreateSession(rec, httptest.NewRequest(http.MethodGet, "/", nil), &saml.Assertion{})
		assert.Check(t, err != nil)
		assert.Check(t, is.Equal("", rec.Header().Get("Set-Cookie")))
	})
}

func TestCovCookieSessionProviderDeleteSession(t *testing.T) {
	t.Run("no cookie", func(t *testing.T) {
		p := covCookieSessionProvider(t)
		rec := httptest.NewRecorder()
		assert.Check(t, p.DeleteSession(rec, httptest.NewRequest(http.MethodGet, "/", nil)))
		assert.Check(t, is.Equal("", rec.Header().Get("Set-Cookie")))
	})

	for _, tc := range []struct{ path, want string }{{"", "/"}, {"/app", "/app"}} {
		t.Run("path "+tc.want, func(t *testing.T) {
			p := covCookieSessionProvider(t)
			p.Path = tc.path
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.AddCookie(&http.Cookie{Name: "token", Value: "abc", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
			rec := httptest.NewRecorder()
			assert.Assert(t, p.DeleteSession(rec, req))
			cookies := rec.Result().Cookies()
			assert.Assert(t, is.Len(cookies, 1))
			c := cookies[0]
			assert.Check(t, is.Equal("token", c.Name))
			assert.Check(t, is.Equal("", c.Value))
			assert.Check(t, is.Equal("sp.example.com", c.Domain))
			// must match the path used by CreateSession or the browser keeps the session
			assert.Check(t, is.Equal(tc.want, c.Path))
			assert.Check(t, c.Expires.Before(time.Unix(2, 0)))
		})
	}
}

func TestCovCookieSessionProviderGetSession(t *testing.T) {
	p := covCookieSessionProvider(t)

	_, err := p.GetSession(httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Check(t, is.Equal(ErrNoSession, err))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "token", Value: "garbage", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	_, err = p.GetSession(req)
	assert.Check(t, is.Equal(ErrNoSession, err))

	rec := httptest.NewRecorder()
	assert.Assert(t, p.CreateSession(rec, httptest.NewRequest(http.MethodGet, "/", nil), &saml.Assertion{}))
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(rec.Result().Cookies()[0])
	s, err := p.GetSession(req)
	assert.Assert(t, err)
	assert.Check(t, s.(JWTSessionClaims).SAMLSession)
}

// --- request_tracker_jwt.go ---

func TestCovJWTTrackedRequestCodecDecode(t *testing.T) {
	codec := covTrackedRequestCodec(t)
	token, err := codec.Encode(TrackedRequest{Index: "abc", SAMLRequestID: "id-1", URI: "/frob"})
	assert.Assert(t, err)

	tr, err := codec.Decode(token)
	assert.Assert(t, err)
	assert.Check(t, is.DeepEqual(&TrackedRequest{Index: "abc", SAMLRequestID: "id-1", URI: "/frob"}, tr))

	_, err = codec.Decode("garbage")
	assert.Check(t, err != nil)

	other := codec
	other.Audience = "https://other.example.com/"
	_, err = other.Decode(token)
	assert.Check(t, errors.Is(err, jwt.ErrTokenInvalidAudience))

	// A session token must not be accepted as a tracked request.
	sc := covSessionCodec(t)
	s, err := sc.New(&saml.Assertion{})
	assert.Assert(t, err)
	sessionToken, err := sc.Encode(s)
	assert.Assert(t, err)
	_, err = codec.Decode(sessionToken)
	assert.Check(t, is.Error(err, "expected saml-authn-request"))
}

// --- request_tracker_cookie.go ---

func covCookieRequestTracker(t *testing.T) CookieRequestTracker {
	t.Helper()
	sp := &saml.ServiceProvider{AcsURL: mustParseURL("https://sp.example.com/saml/acs")}
	return CookieRequestTracker{
		ServiceProvider: sp,
		NamePrefix:      "saml_",
		Codec:           covTrackedRequestCodec(t),
		MaxAge:          saml.MaxIssueDelay,
		SameSite:        http.SameSiteNoneMode,
	}
}

func TestCovCookieRequestTrackerTrackRequest(t *testing.T) {
	t.Run("random index", func(t *testing.T) {
		tracker := covCookieRequestTracker(t)
		tracker.RelayStateFunc = func(http.ResponseWriter, *http.Request) string { return "" }
		rec := httptest.NewRecorder()
		index, err := tracker.TrackRequest(rec, httptest.NewRequest(http.MethodGet, "/frob", nil), "id-1")
		assert.Assert(t, err)
		assert.Check(t, is.Len(index, 56))
		c := rec.Result().Cookies()[0]
		assert.Check(t, is.Equal("saml_"+index, c.Name))
		assert.Check(t, c.HttpOnly)
		assert.Check(t, c.Secure)
		assert.Check(t, is.Equal("/saml/acs", c.Path))
		assert.Check(t, is.Equal(http.SameSiteNoneMode, c.SameSite))
	})

	t.Run("relay state func", func(t *testing.T) {
		tracker := covCookieRequestTracker(t)
		tracker.RelayStateFunc = func(http.ResponseWriter, *http.Request) string { return "custom" }
		rec := httptest.NewRecorder()
		index, err := tracker.TrackRequest(rec, httptest.NewRequest(http.MethodGet, "/frob", nil), "id-1")
		assert.Assert(t, err)
		assert.Check(t, is.Equal("custom", index))
		assert.Check(t, is.Equal("saml_custom", rec.Result().Cookies()[0].Name))
	})

	t.Run("encode error", func(t *testing.T) {
		tracker := covCookieRequestTracker(t)
		codec := covTrackedRequestCodec(t)
		codec.Key = nil
		tracker.Codec = codec
		rec := httptest.NewRecorder()
		_, err := tracker.TrackRequest(rec, httptest.NewRequest(http.MethodGet, "/frob", nil), "id-1")
		assert.Check(t, err != nil)
		assert.Check(t, is.Equal("", rec.Header().Get("Set-Cookie")))
	})
}

func TestCovCookieRequestTrackerStopTracking(t *testing.T) {
	tracker := covCookieRequestTracker(t)
	err := tracker.StopTrackingRequest(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil), "abc")
	assert.Check(t, is.Equal(http.ErrNoCookie, err))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "saml_abc", Value: "x", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	rec := httptest.NewRecorder()
	assert.Assert(t, tracker.StopTrackingRequest(rec, req, "abc"))
	c := rec.Result().Cookies()[0]
	assert.Check(t, is.Equal("saml_abc", c.Name))
	assert.Check(t, is.Equal("", c.Value))
	assert.Check(t, is.Equal("/saml/acs", c.Path))
	assert.Check(t, is.Equal("sp.example.com", c.Domain))
}

func TestCovCookieRequestTrackerGetTrackedRequests(t *testing.T) {
	tracker := covCookieRequestTracker(t)
	good, err := tracker.Codec.Encode(TrackedRequest{Index: "good", SAMLRequestID: "id-good", URI: "/a"})
	assert.Assert(t, err)
	// valid token, but stored under another index: must be ignored
	moved, err := tracker.Codec.Encode(TrackedRequest{Index: "other", SAMLRequestID: "id-moved", URI: "/b"})
	assert.Assert(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "unrelated", Value: good, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	req.AddCookie(&http.Cookie{Name: "saml_bad", Value: "garbage", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	req.AddCookie(&http.Cookie{Name: "saml_moved", Value: moved, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	req.AddCookie(&http.Cookie{Name: "saml_good", Value: good, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})

	got := tracker.GetTrackedRequests(req)
	assert.Check(t, is.DeepEqual([]TrackedRequest{{Index: "good", SAMLRequestID: "id-good", URI: "/a"}}, got))
}

func TestCovCookieRequestTrackerGetTrackedRequest(t *testing.T) {
	tracker := covCookieRequestTracker(t)
	good, err := tracker.Codec.Encode(TrackedRequest{Index: "good", SAMLRequestID: "id-good", URI: "/a"})
	assert.Assert(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "saml_bad", Value: "garbage", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	req.AddCookie(&http.Cookie{Name: "saml_moved", Value: good, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	req.AddCookie(&http.Cookie{Name: "saml_good", Value: good, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})

	_, err = tracker.GetTrackedRequest(req, "missing")
	assert.Check(t, is.Equal(http.ErrNoCookie, err))

	_, err = tracker.GetTrackedRequest(req, "bad")
	assert.Check(t, err != nil)

	_, err = tracker.GetTrackedRequest(req, "moved")
	assert.Check(t, is.Error(err, `expected index "moved", got "good"`))

	tr, err := tracker.GetTrackedRequest(req, "good")
	assert.Assert(t, err)
	assert.Check(t, is.Equal("id-good", tr.SAMLRequestID))
}
