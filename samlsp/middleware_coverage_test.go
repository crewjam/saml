package samlsp

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml"
)

// covFailWriter is a ResponseWriter whose Write always fails.
type covFailWriter struct {
	*httptest.ResponseRecorder
}

func (covFailWriter) Write([]byte) (int, error) { return 0, errors.New("cov: write failed") }

// covAssertionHandler is an AssertionHandler returning a fixed error.
type covAssertionHandler struct{ err error }

func (h covAssertionHandler) HandleAssertion(*saml.Assertion) error { return h.err }

// covSessionProvider is a SessionProvider returning fixed errors.
type covSessionProvider struct {
	getErr    error
	createErr error
}

func (p covSessionProvider) CreateSession(http.ResponseWriter, *http.Request, *saml.Assertion) error {
	return p.createErr
}

func (covSessionProvider) DeleteSession(http.ResponseWriter, *http.Request) error { return nil }

func (p covSessionProvider) GetSession(*http.Request) (Session, error) { return nil, p.getErr }

// covRequestTracker wraps CookieRequestTracker and can inject errors.
type covRequestTracker struct {
	CookieRequestTracker
	trackErr error
	stopErr  error
}

func (t covRequestTracker) TrackRequest(w http.ResponseWriter, r *http.Request, id string) (string, error) {
	if t.trackErr != nil {
		return "", t.trackErr
	}
	return t.CookieRequestTracker.TrackRequest(w, r, id)
}

func (t covRequestTracker) StopTrackingRequest(w http.ResponseWriter, r *http.Request, index string) error {
	if t.stopErr != nil {
		return t.stopErr
	}
	return t.CookieRequestTracker.StopTrackingRequest(w, r, index)
}

// covCapturingOnError records the error passed to OnError.
func covCapturingOnError(got *error) func(http.ResponseWriter, *http.Request, error) {
	return func(w http.ResponseWriter, _ *http.Request, err error) {
		*got = err
		http.Error(w, "forbidden", http.StatusTeapot)
	}
}

func covACSRequest(test *MiddlewareTest, trackedRequestID string) *http.Request {
	v := url.Values{}
	v.Set("SAMLResponse", base64.StdEncoding.EncodeToString(test.SamlResponse))
	v.Set("RelayState", "KCosLjAyNDY4Ojw-QEJERkhKTE5QUlRWWFpcXmBiZGZoamxucHJ0dnh6")
	req := httptest.NewRequest(http.MethodPost, "/saml2/acs", strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", "saml_KCosLjAyNDY4Ojw-QEJERkhKTE5QUlRWWFpcXmBiZGZoamxucHJ0dnh6="+
		test.makeTrackedRequest(trackedRequestID))
	return req
}

func TestCovServeMetadataWriteError(t *testing.T) {
	test := covNewMiddlewareTest(t)
	rec := httptest.NewRecorder()
	test.Middleware.ServeMetadata(covFailWriter{rec}, httptest.NewRequest(http.MethodGet, "/saml2/metadata", nil))
	assert.Check(t, is.Equal(http.StatusInternalServerError, rec.Code))
}

func TestCovServeACSParseFormError(t *testing.T) {
	test := covNewMiddlewareTest(t)
	var got error
	test.Middleware.OnError = covCapturingOnError(&got)
	req := httptest.NewRequest(http.MethodPost, "/saml2/acs", strings.NewReader("a=%zz"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	test.Middleware.ServeACS(rec, req)
	assert.Check(t, is.Equal(http.StatusTeapot, rec.Code))
	assert.Check(t, got != nil)
}

func TestCovServeACSAssertionHandlerError(t *testing.T) {
	test := covNewMiddlewareTest(t)
	var got error
	test.Middleware.OnError = covCapturingOnError(&got)
	test.Middleware.AssertionHandler = covAssertionHandler{err: errors.New("cov: rejected")}
	// AllowIDPInitiated adds "" to the accepted request IDs; the tracked request still matches.
	test.Middleware.ServiceProvider.AllowIDPInitiated = true

	rec := httptest.NewRecorder()
	test.Middleware.ServeACS(rec, covACSRequest(test, "id-9e61753d64e928af5a7a341a97f420c9"))
	assert.Check(t, is.Equal(http.StatusTeapot, rec.Code))
	assert.Check(t, is.Error(got, "cov: rejected"))
	assert.Check(t, is.Equal("", rec.Header().Get("Set-Cookie")))
}

func TestCovRequireAccountSessionError(t *testing.T) {
	test := covNewMiddlewareTest(t)
	var got error
	test.Middleware.OnError = covCapturingOnError(&got)
	test.Middleware.Session = covSessionProvider{getErr: errors.New("cov: store down")}
	handler := test.Middleware.RequireAccount(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("not reached")
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/frob", nil))
	assert.Check(t, is.Equal(http.StatusTeapot, rec.Code))
	assert.Check(t, is.Error(got, "cov: store down"))
}

func TestCovHandleStartAuthFlow(t *testing.T) {
	t.Run("explicit redirect binding", func(t *testing.T) {
		test := covNewMiddlewareTest(t)
		test.Middleware.Binding = saml.HTTPRedirectBinding
		rec := httptest.NewRecorder()
		test.Middleware.HandleStartAuthFlow(rec, httptest.NewRequest(http.MethodGet, "/frob", nil))
		assert.Check(t, is.Equal(http.StatusFound, rec.Code))
		assert.Check(t, strings.HasPrefix(rec.Header().Get("Location"), "https://idp.testshib.org/"))
	})

	t.Run("make request error", func(t *testing.T) {
		test := covNewMiddlewareTest(t)
		test.Middleware.Binding = saml.HTTPPostBinding
		test.Middleware.ServiceProvider.SignatureMethod = "cov-bogus"
		rec := httptest.NewRecorder()
		test.Middleware.HandleStartAuthFlow(rec, httptest.NewRequest(http.MethodGet, "/frob", nil))
		assert.Check(t, is.Equal(http.StatusInternalServerError, rec.Code))
		assert.Check(t, is.Equal("", rec.Header().Get("Set-Cookie")))
	})

	t.Run("track request error", func(t *testing.T) {
		test := covNewMiddlewareTest(t)
		test.Middleware.RequestTracker = covRequestTracker{
			CookieRequestTracker: test.Middleware.RequestTracker.(CookieRequestTracker),
			trackErr:             errors.New("cov: track failed"),
		}
		rec := httptest.NewRecorder()
		test.Middleware.HandleStartAuthFlow(rec, httptest.NewRequest(http.MethodGet, "/frob", nil))
		assert.Check(t, is.Equal(http.StatusInternalServerError, rec.Code))
		assert.Check(t, is.Equal("", rec.Header().Get("Location")))
	})

	t.Run("redirect error", func(t *testing.T) {
		test := covNewMiddlewareTest(t)
		test.Middleware.ServiceProvider.SignatureMethod = "cov-bogus"
		rec := httptest.NewRecorder()
		test.Middleware.HandleStartAuthFlow(rec, httptest.NewRequest(http.MethodGet, "/frob", nil))
		assert.Check(t, is.Equal(http.StatusInternalServerError, rec.Code))
		assert.Check(t, is.Equal("", rec.Header().Get("Location")))
	})

	t.Run("post write error", func(t *testing.T) {
		test := covNewMiddlewareTest(t)
		test.Middleware.Binding = saml.HTTPPostBinding
		rec := httptest.NewRecorder()
		test.Middleware.HandleStartAuthFlow(covFailWriter{rec}, httptest.NewRequest(http.MethodGet, "/frob", nil))
		assert.Check(t, is.Equal(http.StatusInternalServerError, rec.Code))
	})

	t.Run("unsupported binding panics", func(t *testing.T) {
		test := covNewMiddlewareTest(t)
		test.Middleware.Binding = saml.HTTPArtifactBinding
		assert.Check(t, is.Panics(func() {
			test.Middleware.HandleStartAuthFlow(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/frob", nil))
		}))
	})
}

func covFormRequest(form url.Values, cookies ...*http.Cookie) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/saml2/acs", bytes.NewReader([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	if err := req.ParseForm(); err != nil {
		panic(err)
	}
	return req
}

func TestCovCreateSessionFromAssertion(t *testing.T) {
	t.Run("idp initiated relay state without cookie", func(t *testing.T) {
		test := covNewMiddlewareTest(t)
		test.Middleware.ServiceProvider.AllowIDPInitiated = true
		rec := httptest.NewRecorder()
		req := covFormRequest(url.Values{"RelayState": {"/landing"}})
		test.Middleware.CreateSessionFromAssertion(rec, req, &saml.Assertion{}, "/default")
		assert.Check(t, is.Equal(http.StatusFound, rec.Code))
		assert.Check(t, is.Equal("/landing", rec.Header().Get("Location")))
	})

	t.Run("no relay state uses default", func(t *testing.T) {
		test := covNewMiddlewareTest(t)
		rec := httptest.NewRecorder()
		test.Middleware.CreateSessionFromAssertion(rec, covFormRequest(url.Values{}), &saml.Assertion{}, "/default")
		assert.Check(t, is.Equal(http.StatusFound, rec.Code))
		assert.Check(t, is.Equal("/default", rec.Header().Get("Location")))
	})

	t.Run("stop tracking error", func(t *testing.T) {
		test := covNewMiddlewareTest(t)
		var got error
		test.Middleware.OnError = covCapturingOnError(&got)
		index := "KCosLjAyNDY4Ojw-QEJERkhKTE5QUlRWWFpcXmBiZGZoamxucHJ0dnh6"
		req := covFormRequest(url.Values{"RelayState": {index}},
			&http.Cookie{Name: "saml_" + index, Value: test.makeTrackedRequest("id-1"), Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
		test.Middleware.RequestTracker = covRequestTracker{
			CookieRequestTracker: test.Middleware.RequestTracker.(CookieRequestTracker),
			stopErr:              errors.New("cov: stop failed"),
		}
		rec := httptest.NewRecorder()
		test.Middleware.CreateSessionFromAssertion(rec, req, &saml.Assertion{}, "/default")
		assert.Check(t, is.Equal(http.StatusTeapot, rec.Code))
		assert.Check(t, is.Error(got, "cov: stop failed"))
	})

	t.Run("create session error", func(t *testing.T) {
		test := covNewMiddlewareTest(t)
		var got error
		test.Middleware.OnError = covCapturingOnError(&got)
		test.Middleware.Session = covSessionProvider{createErr: errors.New("cov: create failed")}
		rec := httptest.NewRecorder()
		test.Middleware.CreateSessionFromAssertion(rec, covFormRequest(url.Values{}), &saml.Assertion{}, "/default")
		assert.Check(t, is.Equal(http.StatusTeapot, rec.Code))
		assert.Check(t, is.Error(got, "cov: create failed"))
		assert.Check(t, is.Equal("", rec.Header().Get("Location")))
	})
}
