package saml

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// While a browser waits, the SOAP requests made before the IdP answers it
// share BackChannelLogoutTimeout: once it has passed, a participant that
// also lists a front-channel SingleLogoutService is logged out through the
// browser instead, so slow SOAP endpoints cannot hold up the logout.
func TestIDPLogoutSOAPTimeBudgetFallsBackToBrowser(t *testing.T) {
	const delay = 250 * time.Millisecond
	pt := newPropagationTest(t)
	slow := func(sp *ServiceProvider, req *LogoutRequest) []byte {
		time.Sleep(delay)
		return soapLogoutResponseBody(sp, req.ID, StatusSuccess, nil)
	}
	first := pt.addSOAPParticipant(t, HTTPRedirectBinding)
	first.respond = slow
	second := pt.addSOAPParticipant(t, HTTPRedirectBinding)
	second.respond = slow
	pt.login(t, first.sp, second.sp)

	saved := BackChannelLogoutTimeout
	BackChannelLogoutTimeout = 400 * time.Millisecond
	t.Cleanup(func() { BackChannelLogoutTimeout = saved })

	start := time.Now()
	w := pt.startLogout(propagationReturnURL)
	elapsed := time.Since(start)

	// The first answers within the budget; the second, which would take
	// it past, is sent the browser.
	assert.Check(t, is.Len(first.requests(), 1))
	assert.Check(t, is.Equal(http.StatusFound, w.Code))
	assert.Check(t, strings.HasPrefix(w.Header().Get("Location"), second.sp.SloURL.String()), w.Header().Get("Location"))
	assert.Check(t, elapsed < 2*delay, "took %s", elapsed)
}

// Once the budget is spent, the SOAP binding is not tried at all.
func TestIDPLogoutSOAPTimeBudgetSpent(t *testing.T) {
	pt := newPropagationTest(t)
	soapSP := pt.addSOAPParticipant(t, HTTPRedirectBinding)
	pt.login(t, soapSP.sp)

	saved := BackChannelLogoutTimeout
	BackChannelLogoutTimeout = 0
	t.Cleanup(func() { BackChannelLogoutTimeout = saved })

	w := pt.startLogout(propagationReturnURL)
	assert.Check(t, is.Len(soapSP.requests(), 0))
	assert.Check(t, is.Equal(http.StatusFound, w.Code))
	assert.Check(t, strings.HasPrefix(w.Header().Get("Location"), soapSP.sp.SloURL.String()), w.Header().Get("Location"))
}
