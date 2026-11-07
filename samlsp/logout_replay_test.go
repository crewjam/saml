package samlsp

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml"
)

type memoryReplayCache map[string]time.Time

func (c memoryReplayCache) Consume(id string, expiresAt time.Time) error {
	if _, seen := c[id]; seen {
		return saml.ErrAssertionReplayed
	}
	c[id] = expiresAt
	return nil
}

// With ServiceProvider.ReplayCache set, ServeSLO answers an IdP-initiated
// LogoutRequest once and refuses the same request again.
func TestServeSLOLogoutRequestReplay(t *testing.T) {
	lt := newLogoutTest(t, saml.HTTPRedirectBinding)
	lt.m.ServiceProvider.ReplayCache = memoryReplayCache{}
	form := url.Values{"SAMLRequest": {lt.signedIDPMessage(t, lt.logoutRequest().Element())}}

	resp := lt.postToSLO(form, lt.sessionCookie(t, "x"))
	assert.Check(t, is.Equal(http.StatusFound, resp.Code))
	assertSessionDeleted(t, lt, resp)

	replay := lt.postToSLO(form, lt.sessionCookie(t, "x"))
	assert.Check(t, is.Equal(http.StatusForbidden, replay.Code))
	assert.Check(t, is.Len(replay.Result().Cookies(), 0))
}
