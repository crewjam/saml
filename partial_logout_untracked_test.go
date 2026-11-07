package saml

import (
	"errors"
	"net/http"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// sloTrackingSessionProvider is a fakeSLOSessionProvider that also
// implements SessionParticipantTracker, with no other participants.
type sloTrackingSessionProvider struct {
	*fakeSLOSessionProvider
	listErr error
}

func (p *sloTrackingSessionProvider) AddSessionParticipant(*http.Request, *Session, SessionParticipant) error {
	return nil
}

func (p *sloTrackingSessionProvider) SessionParticipants(*http.Request, func(*Session) bool) ([]SessionParticipant, error) {
	return nil, p.listErr
}

// Without a SessionParticipantTracker, the IdP cannot contact the other
// session participants. saml-core-2.0-os §3.7.3.2 then requires the
// second-level status PartialLogout, which is reported only when
// ReportPartialLogoutWithoutTracker is set.
func TestIDPServeSLOPartialLogoutWithoutTracker(t *testing.T) {
	for _, tc := range []struct {
		name   string
		report bool
		second string
	}{
		{"default", false, ""},
		{"ReportPartialLogoutWithoutTracker", true, StatusPartialLogout},
	} {
		t.Run(tc.name, func(t *testing.T) {
			test := newSLOTest(t)
			test.IDP.ReportPartialLogoutWithoutTracker = tc.report

			resp := decodeLogoutResponse(t, test.serve(test.redirectRequest(t, test.logoutRequest())))
			checkStatus(t, resp, StatusSuccess, tc.second)
			assert.Check(t, is.Len(test.sessions.invalidated, 1), "the session is ended")
		})
	}
}

// The option does not report PartialLogout when the session could not be
// ended: the top-level status is Responder.
func TestIDPServeSLOPartialLogoutWithoutTrackerSessionNotEnded(t *testing.T) {
	test := newSLOTest(t)
	test.IDP.ReportPartialLogoutWithoutTracker = true
	test.sessions.err = errors.New("store unavailable")

	resp := decodeLogoutResponse(t, test.serve(test.redirectRequest(t, test.logoutRequest())))
	checkStatus(t, resp, StatusResponder, "")
}

// With a SessionParticipantTracker the option changes nothing: the
// second-level status reports whether the participants were logged out.
func TestIDPServeSLOPartialLogoutWithTracker(t *testing.T) {
	for _, tc := range []struct {
		name    string
		report  bool
		listErr error
		second  string
	}{
		{"no other participants", false, nil, ""},
		{"no other participants, option set", true, nil, ""},
		{"participants cannot be listed", false, errors.New("store unavailable"), StatusPartialLogout},
		{"participants cannot be listed, option set", true, errors.New("store unavailable"), StatusPartialLogout},
	} {
		t.Run(tc.name, func(t *testing.T) {
			test := newSLOTest(t)
			test.IDP.SessionProvider = &sloTrackingSessionProvider{fakeSLOSessionProvider: test.sessions, listErr: tc.listErr}
			test.IDP.ReportPartialLogoutWithoutTracker = tc.report

			resp := decodeLogoutResponse(t, test.serve(test.redirectRequest(t, test.logoutRequest())))
			checkStatus(t, resp, StatusSuccess, tc.second)
		})
	}
}

// The option applies to LogoutRequests sent with the SOAP binding too.
func TestIDPServeSLOOverSOAPPartialLogoutWithoutTracker(t *testing.T) {
	for _, tc := range []struct {
		name   string
		report bool
		second string
	}{
		{"default", false, ""},
		{"ReportPartialLogoutWithoutTracker", true, StatusPartialLogout},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := newSOAPLogoutTest(t)
			sessions := &fakeSLOSessionProvider{
				sessions: []*Session{{ID: "idp-session", NameID: "alice@example.com", Index: "idp-session-index"}},
			}
			st.idp.SessionProvider = sessions
			st.idp.ReportPartialLogoutWithoutTracker = tc.report

			req := st.logoutRequest(t, st.initiator, nil)
			resp := soapLogoutResponse(t, st.initiator, st.postSOAP(soapEnvelopeBytes(t, req)))
			checkStatus(t, resp, StatusSuccess, tc.second)
			assert.Check(t, is.Len(sessions.invalidated, 1), "the session is ended")
		})
	}
}
