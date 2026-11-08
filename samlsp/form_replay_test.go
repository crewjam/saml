package samlsp

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml"
)

const testTrackedIndex = "KCosLjAyNDY4Ojw-QEJERkhKTE5QUlRWWFpcXmBiZGZoamxucHJ0dnh6"

// acsRequest returns the POST of the test SAML response to the ACS URL, with
// a tracked request cookie for uri.
func (test *MiddlewareTest) acsRequest(t *testing.T, uri string) *http.Request {
	codec := test.Middleware.RequestTracker.(CookieRequestTracker).Codec
	token, err := codec.Encode(TrackedRequest{
		Index:         testTrackedIndex,
		SAMLRequestID: "id-9e61753d64e928af5a7a341a97f420c9",
		URI:           uri,
	})
	assert.NilError(t, err)

	v := url.Values{}
	v.Set("SAMLResponse", base64.StdEncoding.EncodeToString(test.SamlResponse))
	v.Set("RelayState", testTrackedIndex)
	req := httptest.NewRequest(http.MethodPost, "/saml2/acs", strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", "saml_"+testTrackedIndex+"="+token)
	req.RemoteAddr = testClientAddr
	return req
}

// testClientAddr is the address of the user agent in the test Response:
// its SubjectConfirmationData Address, which ServiceProvider.ParseResponse
// checks against the request's RemoteAddr.
const testClientAddr = "75.144.86.91:54321"

// formPost returns a same-origin POST of form to uri.
func formPost(uri string, form url.Values) *http.Request {
	req := httptest.NewRequest(http.MethodPost, uri, strings.NewReader(form.Encode()))
	req.Host = "15661444.ngrok.io"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	return req
}

func startAuthFlow(test *MiddlewareTest, req *http.Request) *httptest.ResponseRecorder {
	handler := test.Middleware.RequireAccount(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		panic("not reached")
	}))
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	return resp
}

func TestFormReplayOffByDefault(t *testing.T) {
	test := NewMiddlewareTest(t)
	assert.Check(t, test.Middleware.FormReplayStore == nil)

	resp := startAuthFlow(test, formPost("/frob", url.Values{"a": {"b"}}))
	assert.Check(t, is.Equal(http.StatusFound, resp.Code))

	// after login, the user is sent to the tracked URI with a GET request
	resp = httptest.NewRecorder()
	test.Middleware.ServeHTTP(resp, test.acsRequest(t, "/frob"))
	assert.Check(t, is.Equal(http.StatusFound, resp.Code))
	assert.Check(t, is.Equal("/frob", resp.Header().Get("Location")))
}

func TestFormReplaySavesSameOriginPost(t *testing.T) {
	test := NewMiddlewareTest(t)
	store := &MemoryFormReplayStore{}
	test.Middleware.FormReplayStore = store

	resp := startAuthFlow(test, formPost("/frob?x=1", url.Values{"a": {"b", "c"}}))
	assert.Check(t, is.Equal(http.StatusFound, resp.Code))

	saved, ok, err := store.TakeForm(nil, testTrackedIndex)
	assert.NilError(t, err)
	assert.Assert(t, ok)
	assert.Check(t, is.Equal("/frob?x=1", saved.URI))
	assert.Check(t, is.DeepEqual(url.Values{"a": {"b", "c"}}, saved.Form))

	// a form is taken only once
	_, ok, err = store.TakeForm(nil, testTrackedIndex)
	assert.NilError(t, err)
	assert.Check(t, !ok)
}

func TestFormReplayDoesNotSave(t *testing.T) {
	for name, tc := range map[string]struct {
		modify func(*http.Request)
		store  *MemoryFormReplayStore
	}{
		"cross-site": {modify: func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }},
		"same-site":  {modify: func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-site") }},
		"no origin":  {modify: func(r *http.Request) { r.Header.Del("Sec-Fetch-Site") }},
		"other origin": {modify: func(r *http.Request) {
			r.Header.Del("Sec-Fetch-Site")
			r.Header.Set("Origin", "https://evil.example")
		}},
		"null origin": {modify: func(r *http.Request) {
			r.Header.Del("Sec-Fetch-Site")
			r.Header.Set("Origin", "null")
		}},
		"multipart": {modify: func(r *http.Request) {
			r.Header.Set("Content-Type", "multipart/form-data; boundary=x")
		}},
		"not allowed": {
			modify: func(*http.Request) {},
			store:  &MemoryFormReplayStore{Allow: func(*http.Request) bool { return false }},
		},
	} {
		t.Run(name, func(t *testing.T) {
			test := NewMiddlewareTest(t)
			store := tc.store
			if store == nil {
				store = &MemoryFormReplayStore{}
			}
			test.Middleware.FormReplayStore = store

			req := formPost("/frob", url.Values{"a": {"b"}})
			tc.modify(req)
			resp := startAuthFlow(test, req)
			assert.Check(t, is.Equal(http.StatusFound, resp.Code))

			_, ok, err := store.TakeForm(nil, testTrackedIndex)
			assert.NilError(t, err)
			assert.Check(t, !ok)
		})
	}
}

func TestFormReplaySavesMatchingOriginHeader(t *testing.T) {
	test := NewMiddlewareTest(t)
	store := &MemoryFormReplayStore{}
	test.Middleware.FormReplayStore = store

	req := formPost("/frob", url.Values{"a": {"b"}})
	req.Header.Del("Sec-Fetch-Site")
	req.Header.Set("Origin", "https://15661444.ngrok.io")
	startAuthFlow(test, req)

	_, ok, err := store.TakeForm(nil, testTrackedIndex)
	assert.NilError(t, err)
	assert.Check(t, ok)
}

func TestFormReplayTooLarge(t *testing.T) {
	test := NewMiddlewareTest(t)
	store := &MemoryFormReplayStore{MaxFormSize: 16}
	test.Middleware.FormReplayStore = store
	var gotErr error
	test.Middleware.OnError = func(w http.ResponseWriter, _ *http.Request, err error) {
		gotErr = err
		w.WriteHeader(http.StatusRequestEntityTooLarge)
	}

	resp := startAuthFlow(test, formPost("/frob", url.Values{"a": {strings.Repeat("x", 32)}}))
	assert.Check(t, is.Equal(http.StatusRequestEntityTooLarge, resp.Code))
	assert.Check(t, errors.Is(gotErr, ErrFormTooLarge))

	// the same limit applies to a form the application has parsed already
	req := formPost("/frob", url.Values{"a": {strings.Repeat("x", 32)}})
	assert.NilError(t, req.ParseForm())
	_, err := store.SaveForm(req, "i")
	assert.Check(t, errors.Is(err, ErrFormTooLarge))
}

func TestFormReplayStoreLimits(t *testing.T) {
	now := saml.TimeNow()
	defer func() { saml.TimeNow = time.Now }()
	saml.TimeNow = func() time.Time { return now }

	store := &MemoryFormReplayStore{MaxEntries: 1, MaxAge: time.Minute}
	ok, err := store.SaveForm(formPost("/a", url.Values{}), "1")
	assert.NilError(t, err)
	assert.Check(t, ok)

	// the store is full
	ok, err = store.SaveForm(formPost("/a", url.Values{}), "2")
	assert.NilError(t, err)
	assert.Check(t, !ok)

	// expired forms are dropped, and are not returned
	now = now.Add(2 * time.Minute)
	ok, err = store.SaveForm(formPost("/a", url.Values{}), "3")
	assert.NilError(t, err)
	assert.Check(t, ok)
	_, ok, _ = store.TakeForm(nil, "1")
	assert.Check(t, !ok)

	now = now.Add(2 * time.Minute)
	_, ok, _ = store.TakeForm(nil, "3")
	assert.Check(t, !ok)
}

func TestFormReplayAfterLogin(t *testing.T) {
	test := NewMiddlewareTest(t)
	store := &MemoryFormReplayStore{}
	test.Middleware.FormReplayStore = store

	uri := `/frob?q="><script>alert(1)</script>`
	_, err := store.SaveForm(formPost(uri, url.Values{
		`a"><script>alert(2)</script>`: {`v"><script>alert(3)</script>`, "plain"},
		"b":                            {"&<>'"},
	}), testTrackedIndex)
	assert.NilError(t, err)

	resp := httptest.NewRecorder()
	test.Middleware.ServeHTTP(resp, test.acsRequest(t, uri))
	assert.Check(t, is.Equal(http.StatusOK, resp.Code))

	body := resp.Body.String()
	assert.Check(t, !strings.Contains(body, "<script>alert"), body)
	assert.Check(t, is.Equal(1, strings.Count(body, "<script")), body)
	assert.Check(t, is.Contains(body, `<form method="post" action="/frob?q=%22%3e%3cscript%3ealert%281%29%3c/script%3e" id="SAMLReplayForm">`))
	assert.Check(t, is.Contains(body, `<input type="hidden" name="a&#34;&gt;&lt;script&gt;alert(2)&lt;/script&gt;" value="v&#34;&gt;&lt;script&gt;alert(3)&lt;/script&gt;" />`))
	assert.Check(t, is.Contains(body, `<input type="hidden" name="a&#34;&gt;&lt;script&gt;alert(2)&lt;/script&gt;" value="plain" />`))
	assert.Check(t, is.Contains(body, `<input type="hidden" name="b" value="&amp;&lt;&gt;&#39;" />`))

	sum := sha256.Sum256([]byte(replayScript))
	assert.Check(t, is.Equal("sha256-"+base64.StdEncoding.EncodeToString(sum[:]), replayScriptHash))
	assert.Check(t, is.Equal("default-src; script-src '"+replayScriptHash+"'; reflected-xss block; referrer no-referrer;",
		resp.Header().Get("Content-Security-Policy")))
	assert.Check(t, is.Equal("text/html", resp.Header().Get("Content-Type")))
	assert.Check(t, is.Equal("no-cache, no-store", resp.Header().Get("Cache-Control")))

	// the session is created as usual
	assert.Check(t, is.Contains(strings.Join(resp.Header()["Set-Cookie"], "\n"), "ttt="+test.expectedSessionCookie))

	// the form is replayed once only
	resp = httptest.NewRecorder()
	test.Middleware.ServeHTTP(resp, test.acsRequest(t, uri))
	assert.Check(t, is.Equal(http.StatusFound, resp.Code))
}

func TestFormReplayScriptNonce(t *testing.T) {
	test := NewMiddlewareTest(t)
	store := &MemoryFormReplayStore{}
	test.Middleware.FormReplayStore = store
	test.Middleware.ScriptNonce = func(*http.Request) string { return "n0nce" }

	_, err := store.SaveForm(formPost("/frob", url.Values{"a": {"b"}}), testTrackedIndex)
	assert.NilError(t, err)

	resp := httptest.NewRecorder()
	test.Middleware.ServeHTTP(resp, test.acsRequest(t, "/frob"))
	assert.Check(t, is.Equal(http.StatusOK, resp.Code))
	assert.Check(t, is.Contains(resp.Body.String(), `<script nonce="n0nce">`+replayScript+`</script>`))
}

func TestFormReplayURIMismatch(t *testing.T) {
	test := NewMiddlewareTest(t)
	store := &MemoryFormReplayStore{}
	test.Middleware.FormReplayStore = store

	_, err := store.SaveForm(formPost("/other", url.Values{"a": {"b"}}), testTrackedIndex)
	assert.NilError(t, err)

	resp := httptest.NewRecorder()
	test.Middleware.ServeHTTP(resp, test.acsRequest(t, "/frob"))
	assert.Check(t, is.Equal(http.StatusFound, resp.Code))
	assert.Check(t, is.Equal("/frob", resp.Header().Get("Location")))
}

func TestFormReplayTakeFormError(t *testing.T) {
	test := NewMiddlewareTest(t)
	test.Middleware.FormReplayStore = failingFormStore{}
	var gotErr error
	test.Middleware.OnError = func(w http.ResponseWriter, _ *http.Request, err error) {
		gotErr = err
		w.WriteHeader(http.StatusForbidden)
	}

	resp := httptest.NewRecorder()
	test.Middleware.ServeHTTP(resp, test.acsRequest(t, "/frob"))
	assert.Check(t, is.Equal(http.StatusForbidden, resp.Code))
	assert.Check(t, is.ErrorContains(gotErr, "store failed"))
}

type failingFormStore struct{}

func (failingFormStore) SaveForm(*http.Request, string) (bool, error) {
	return false, errors.New("store failed")
}

func (failingFormStore) TakeForm(*http.Request, string) (*SavedForm, bool, error) {
	return nil, false, errors.New("store failed")
}

func TestFormReplayEmptyBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/frob", bytes.NewReader(nil))
	req.Body = nil
	form, err := readPostForm(req, 10)
	assert.NilError(t, err)
	assert.Check(t, is.Len(form, 0))
}
