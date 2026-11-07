package saml

import (
	"testing"
	"time"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// The other participants of a logout that came over SOAP are contacted at
// the same time, not one after the other, and a participant that does not
// answer within BackChannelLogoutTimeout counts as not logged out, so that
// the service provider that asked still gets its answer in time.
func TestIDPServeSLOOverSOAPContactsParticipantsConcurrently(t *testing.T) {
	const delay = 300 * time.Millisecond
	st := newSOAPLogoutTest(t)
	var participants []*soapParticipant
	// One after the other, they would take longer than the timeout.
	for i := 0; i < 5; i++ {
		p := st.addSOAPParticipant(t)
		p.respond = func(sp *ServiceProvider, req *LogoutRequest) []byte {
			time.Sleep(delay)
			return soapLogoutResponseBody(sp, req.ID, StatusSuccess, nil)
		}
		participants = append(participants, p)
	}
	hung := st.addSOAPParticipant(t)
	hung.respond = func(sp *ServiceProvider, req *LogoutRequest) []byte {
		time.Sleep(1500 * time.Millisecond)
		return soapLogoutResponseBody(sp, req.ID, StatusSuccess, nil)
	}
	sps := make([]*ServiceProvider, 0, 2+len(participants))
	sps = append(sps, st.initiator, hung.sp)
	for _, p := range participants {
		sps = append(sps, p.sp)
	}
	st.login(t, sps...)

	saved := BackChannelLogoutTimeout
	BackChannelLogoutTimeout = time.Second
	t.Cleanup(func() { BackChannelLogoutTimeout = saved })

	start := time.Now()
	resp := soapLogoutResponse(t, st.initiator, st.postSOAP(soapEnvelopeBytes(t, st.logoutRequest(t, st.initiator, nil))))
	elapsed := time.Since(start)

	checkStatus(t, resp, StatusSuccess, StatusPartialLogout)
	assert.Check(t, elapsed < 2*time.Second, "took %s", elapsed)
	for _, p := range participants {
		assert.Check(t, is.Len(p.requests(), 1))
	}
}
