package samlsp

import (
	"net/http"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml"
)

// opaqueSession is a session that knows its NameID but does not implement
// RevocableSession.
type opaqueSession struct {
	claims JWTSessionClaims
}

func (s opaqueSession) GetNameID() string { return s.claims.GetNameID() }

// opaqueSessionCodec is a custom SessionCodec that makes sessions a
// CookieSessionProvider cannot check against its Revocations, and does not
// implement RevocableSessionCodec.
type opaqueSessionCodec struct {
	jwt JWTSessionCodec
}

func (c opaqueSessionCodec) New(assertion *saml.Assertion) (Session, error) {
	return c.jwt.New(assertion)
}

func (c opaqueSessionCodec) Encode(s Session) (string, error) {
	return c.jwt.Encode(s)
}

func (c opaqueSessionCodec) Decode(value string) (Session, error) {
	s, err := c.jwt.Decode(value)
	if err != nil {
		return nil, err
	}
	return opaqueSession{claims: s.(JWTSessionClaims)}, nil
}

// declaringSessionCodec is a custom SessionCodec that implements
// RevocableSessionCodec: if revocable is set, it makes RevocableSessions and
// says so; otherwise it makes opaque sessions and says so.
type declaringSessionCodec struct {
	opaqueSessionCodec
	revocable bool
}

func (c declaringSessionCodec) Decode(value string) (Session, error) {
	if c.revocable {
		return c.jwt.Decode(value)
	}
	return c.opaqueSessionCodec.Decode(value)
}

func (c declaringSessionCodec) RevocableSessions() bool {
	return c.revocable
}

// A CookieSessionProvider whose Codec does not declare that its sessions
// can be revoked answers a SOAP LogoutRequest with Responder rather than
// Success: GetSession could not refuse those sessions, which would stay
// usable after the IdP had been told they were ended.
func TestServeSLOSOAPLogoutRequestCodecWithoutRevocation(t *testing.T) {
	for _, tc := range []struct {
		name        string
		codec       func(JWTSessionCodec) SessionCodec
		wantRevoked bool
	}{
		{"custom codec", func(c JWTSessionCodec) SessionCodec {
			return opaqueSessionCodec{jwt: c}
		}, false},
		{"custom codec declaring no support", func(c JWTSessionCodec) SessionCodec {
			return declaringSessionCodec{opaqueSessionCodec: opaqueSessionCodec{jwt: c}}
		}, false},
		{"custom codec declaring support", func(c JWTSessionCodec) SessionCodec {
			return declaringSessionCodec{opaqueSessionCodec: opaqueSessionCodec{jwt: c}, revocable: true}
		}, true},
		{"JWT codec", func(c JWTSessionCodec) SessionCodec {
			return c
		}, true},
		{"JWT codec pointer", func(c JWTSessionCodec) SessionCodec {
			return &c
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := newSOAPLogoutApp(t)
			alice := app.cookie(t, "alice@example.com", logoutTestNow, "index-1")
			provider := app.lt.m.Session.(CookieSessionProvider)
			provider.Codec = tc.codec(provider.Codec.(JWTSessionCodec))
			app.lt.m.Session = provider
			assert.Check(t, is.Equal(app.get(t, alice), http.StatusOK))

			status, body := app.post(t, "text/xml", app.idpSOAP(t, app.soapLogoutRequest("index-1")))
			assert.Check(t, is.Equal(status, http.StatusOK))
			gotStatus := app.logoutResponseStatus(t, body)
			if tc.wantRevoked {
				assert.Check(t, is.Equal(gotStatus, saml.StatusSuccess))
				assert.Check(t, is.Len(app.errors, 0))
				assert.Check(t, is.Equal(app.get(t, alice), http.StatusFound))
				return
			}
			assert.Check(t, is.Equal(gotStatus, saml.StatusResponder))
			assert.Assert(t, is.Len(app.errors, 1))
			assert.Check(t, is.ErrorIs(app.errors[0], errSOAPLogoutNotTerminated))
			assert.Check(t, is.ErrorIs(app.errors[0], ErrSessionTerminationUnsupported))
			// Nothing was recorded, and the session is still accepted, as
			// the Responder status tells the IdP.
			assert.Check(t, is.Len(provider.Revocations.(*MemorySessionRevocationStore).entries, 0))
			assert.Check(t, is.Equal(app.get(t, alice), http.StatusOK))
		})
	}
}
