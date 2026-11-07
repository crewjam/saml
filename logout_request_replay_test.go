package saml

import (
	"errors"
	"net/http"
	"testing"
	"time"

	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// The service provider records each LogoutRequest it accepts in its
// ReplayCache and refuses the same request again, with each binding.
func TestValidateLogoutRequestRefusesReplay(t *testing.T) {
	e := spcovSetup(t)
	requestKey := logoutRequestReplayKeyPrefix + e.logoutRequest().ID
	unsigned := spcovSerialize(t, e.logoutRequest().Element())
	redirect := redirectQuery{param: "SAMLRequest", xml: unsigned, sigAlg: dsig.RSASHA256SignatureMethod, key: e.idpKey}

	for _, tc := range []struct {
		name    string
		request func(t *testing.T) *http.Request
	}{
		{"redirect", func(t *testing.T) *http.Request {
			return redirectRequest(e.sp, redirect.build(t))
		}},
		{"post", func(t *testing.T) *http.Request {
			return postRequestBytes(e.sp.SloURL.String(), spcovSerialize(t, e.idpSign(t, e.logoutRequest().Element())))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cache := memoryReplayCache{}
			e.sp.ReplayCache = cache
			t.Cleanup(func() { e.sp.ReplayCache = nil })

			req, err := e.sp.ValidateLogoutRequest(tc.request(t))
			assert.NilError(t, err)
			assert.Check(t, is.Equal(e.logoutRequest().ID, req.ID))
			assert.Check(t, is.DeepEqual(memoryReplayCache{requestKey: spcovNow.Add(MaxIssueDelay)}, cache))

			req, err = e.sp.ValidateLogoutRequest(tc.request(t))
			assert.Check(t, is.Nil(req))
			assert.Check(t, is.ErrorIs(spcovPrivateErr(t, err), ErrAssertionReplayed))
		})
	}
}

// Without a ReplayCache, the same LogoutRequest is accepted again, as before.
func TestValidateLogoutRequestWithoutReplayCache(t *testing.T) {
	e := spcovSetup(t)
	unsigned := spcovSerialize(t, e.logoutRequest().Element())
	q := redirectQuery{param: "SAMLRequest", xml: unsigned, sigAlg: dsig.RSASHA256SignatureMethod, key: e.idpKey}
	for i := 0; i < 2; i++ {
		_, err := e.sp.ValidateLogoutRequest(redirectRequest(e.sp, q.build(t)))
		assert.NilError(t, err)
	}
}

func TestValidateLogoutRequestReplayCacheDetails(t *testing.T) {
	e := spcovSetup(t)
	sign := func(t *testing.T, req *LogoutRequest) *http.Request {
		return postRequestBytes(e.sp.SloURL.String(), spcovSerialize(t, e.idpSign(t, req.Element())))
	}

	t.Run("expiry is bounded by NotOnOrAfter", func(t *testing.T) {
		cache := memoryReplayCache{}
		e.sp.ReplayCache = cache
		req := e.logoutRequest()
		notOnOrAfter := spcovNow.Add(-2 * time.Minute)
		req.NotOnOrAfter = &notOnOrAfter
		_, err := e.sp.ValidateLogoutRequest(sign(t, req))
		assert.NilError(t, err)
		assert.Check(t, is.DeepEqual(memoryReplayCache{logoutRequestReplayKeyPrefix + req.ID: notOnOrAfter.Add(MaxClockSkew)}, cache))
	})

	t.Run("a later NotOnOrAfter does not extend the expiry", func(t *testing.T) {
		cache := memoryReplayCache{}
		e.sp.ReplayCache = cache
		req := e.logoutRequest()
		notOnOrAfter := spcovNow.Add(time.Hour)
		req.NotOnOrAfter = &notOnOrAfter
		_, err := e.sp.ValidateLogoutRequest(sign(t, req))
		assert.NilError(t, err)
		assert.Check(t, is.DeepEqual(memoryReplayCache{logoutRequestReplayKeyPrefix + req.ID: spcovNow.Add(MaxIssueDelay)}, cache))
	})

	t.Run("an assertion ID does not collide with a LogoutRequest ID", func(t *testing.T) {
		cache := memoryReplayCache{}
		e.sp.ReplayCache = cache
		req := e.logoutRequest()
		assert.NilError(t, cache.Consume(req.ID, spcovNow.Add(time.Hour)))
		_, err := e.sp.ValidateLogoutRequest(sign(t, req))
		assert.NilError(t, err)
	})

	t.Run("an invalid request is not recorded", func(t *testing.T) {
		cache := memoryReplayCache{}
		e.sp.ReplayCache = cache
		req := e.logoutRequest()
		req.Destination = "https://other.example.com/slo"
		_, err := e.sp.ValidateLogoutRequest(sign(t, req))
		assert.Check(t, err != nil)
		assert.Check(t, is.Len(cache, 0))
	})

	t.Run("a request without an ID is refused", func(t *testing.T) {
		e.sp.ReplayCache = memoryReplayCache{}
		req := e.logoutRequest()
		req.ID = ""
		_, err := e.sp.ValidateLogoutRequest(sign(t, req))
		assert.Check(t, is.ErrorIs(spcovPrivateErr(t, err), ErrMissingElement))
	})

	t.Run("a failing cache refuses the request", func(t *testing.T) {
		e.sp.ReplayCache = failingReplayCache{}
		_, err := e.sp.ValidateLogoutRequest(sign(t, e.logoutRequest()))
		assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), "store unavailable"))
	})
}

// The IdP records each LogoutRequest ServeSLO accepts in its ReplayCache and
// answers the same request again with HTTP 400, without ending a session.
func TestIDPServeSLORefusesReplay(t *testing.T) {
	for _, tc := range []struct {
		name    string
		request func(t *testing.T, test *sloTest, req *LogoutRequest) *http.Request
	}{
		{"redirect", func(t *testing.T, test *sloTest, req *LogoutRequest) *http.Request {
			return test.redirectRequest(t, req)
		}},
		{"post", func(t *testing.T, test *sloTest, req *LogoutRequest) *http.Request {
			return test.signedPostRequest(t, req)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			test := newSLOTest(t)
			cache := memoryReplayCache{}
			test.IDP.ReplayCache = cache
			req := test.logoutRequest()

			w := test.serve(tc.request(t, test, req))
			assert.Check(t, w.Code == http.StatusFound || w.Code == http.StatusOK, w.Body.String())
			assert.Check(t, is.Equal(1, test.sessions.calls))
			assert.Check(t, is.DeepEqual(memoryReplayCache{
				logoutRequestReplayKeyPrefix + req.ID: req.IssueInstant.Add(MaxIssueDelay),
			}, cache))

			w = test.serve(tc.request(t, test, req))
			assert.Check(t, is.Equal(http.StatusBadRequest, w.Code))
			assert.Check(t, is.Equal(1, test.sessions.calls))
		})
	}
}

func TestIDPLogoutRequestReplayCacheDetails(t *testing.T) {
	t.Run("expiry is bounded by NotOnOrAfter", func(t *testing.T) {
		test := newSLOTest(t)
		cache := memoryReplayCache{}
		test.IDP.ReplayCache = cache
		req := test.logoutRequest()
		notOnOrAfter := req.IssueInstant.Add(-2 * time.Minute)
		req.NotOnOrAfter = &notOnOrAfter
		w := test.serve(test.redirectRequest(t, req))
		assert.Check(t, is.Equal(http.StatusFound, w.Code))
		assert.Check(t, is.DeepEqual(memoryReplayCache{logoutRequestReplayKeyPrefix + req.ID: notOnOrAfter.Add(MaxClockSkew)}, cache))
	})

	t.Run("an invalid request is not recorded", func(t *testing.T) {
		test := newSLOTest(t)
		cache := memoryReplayCache{}
		test.IDP.ReplayCache = cache
		req := test.logoutRequest()
		req.Destination = "https://other-idp.example.com/saml/slo"
		w := test.serve(test.redirectRequest(t, req))
		assert.Check(t, is.Equal(http.StatusBadRequest, w.Code))
		assert.Check(t, is.Len(cache, 0))
	})

	t.Run("a failing cache refuses the request", func(t *testing.T) {
		test := newSLOTest(t)
		test.IDP.ReplayCache = failingReplayCache{}
		r := test.redirectRequest(t, test.logoutRequest())
		req, err := NewIdpLogoutRequest(&test.IDP, r)
		assert.NilError(t, err)
		assert.Check(t, is.ErrorContains(req.Validate(), "store unavailable"))
		assert.Check(t, is.Equal(http.StatusBadRequest, test.serve(r).Code))
		assert.Check(t, is.Equal(0, test.sessions.calls))
	})

	t.Run("replay error matches ErrAssertionReplayed", func(t *testing.T) {
		test := newSLOTest(t)
		test.IDP.ReplayCache = memoryReplayCache{}
		logoutRequest := test.logoutRequest()
		for i, wantErr := range []error{nil, ErrAssertionReplayed} {
			req, err := NewIdpLogoutRequest(&test.IDP, test.redirectRequest(t, logoutRequest))
			assert.NilError(t, err)
			err = req.Validate()
			if wantErr == nil {
				assert.Check(t, is.Nil(err), "attempt %d", i)
			} else {
				assert.Check(t, errors.Is(err, wantErr), "attempt %d: %v", i, err)
			}
		}
	})

	t.Run("without a ReplayCache the request is accepted again", func(t *testing.T) {
		test := newSLOTest(t)
		req := test.logoutRequest()
		for i := 0; i < 2; i++ {
			assert.Check(t, is.Equal(http.StatusFound, test.serve(test.redirectRequest(t, req)).Code))
		}
		assert.Check(t, is.Equal(2, test.sessions.calls))
	})
}
