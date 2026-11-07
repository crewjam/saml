package saml

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// plainHTTPServer serves handler over plain http, and counts the requests it
// gets.
func plainHTTPServer(t *testing.T, handler http.Handler) (*httptest.Server, *int) {
	t.Helper()
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// The service provider sends SOAP LogoutRequests only to an https
// SingleLogoutService, unless AllowInsecureSOAPEndpoints is set.
func TestSOAPLogoutRequestRequiresHTTPS(t *testing.T) {
	setup := func(t *testing.T) (*spcovEnv, *int) {
		e := spcovSetup(t)
		s := newSOAPLogoutIDPServer(t, e)
		s.respond = func(req *LogoutRequest) []byte { return e.idpSOAPLogoutResponse(t, req, true, nil) }
		plain, hits := plainHTTPServer(t, s.Config.Handler)
		slos := e.sp.IDPMetadata.IDPSSODescriptors[0].SingleLogoutServices
		slos[len(slos)-1].Location = plain.URL
		e.sp.HTTPClient = plain.Client()
		return e, hits
	}

	t.Run("make refuses http", func(t *testing.T) {
		e, hits := setup(t)
		_, err := e.sp.MakeSOAPLogoutRequest(NameID{Value: "alice"})
		assert.Check(t, is.ErrorIs(err, ErrInsecureSOAPEndpoint))
		assert.Check(t, is.Equal(*hits, 0))
	})
	t.Run("send refuses http", func(t *testing.T) {
		e, hits := setup(t)
		e.sp.AllowInsecureSOAPEndpoints = true
		req, err := e.sp.MakeSOAPLogoutRequest(NameID{Value: "alice"})
		assert.NilError(t, err)
		e.sp.AllowInsecureSOAPEndpoints = false
		_, err = e.sp.SendSOAPLogoutRequest(context.Background(), req)
		assert.Check(t, is.ErrorIs(err, ErrInsecureSOAPEndpoint))
		assert.Check(t, is.Equal(*hits, 0))
	})
	t.Run("allowed", func(t *testing.T) {
		e, hits := setup(t)
		e.sp.AllowInsecureSOAPEndpoints = true
		req, err := e.sp.MakeSOAPLogoutRequest(NameID{Value: "alice"})
		assert.NilError(t, err)
		resp, err := e.sp.SendSOAPLogoutRequest(context.Background(), req)
		assert.NilError(t, err)
		assert.Check(t, is.Equal(resp.InResponseTo, req.ID))
		assert.Check(t, is.Equal(*hits, 1))
	})
}

// The service provider sends attribute queries only to an https
// AttributeService, unless AllowInsecureSOAPEndpoints is set.
func TestAttributeQueryRequiresHTTPS(t *testing.T) {
	setup := func(t *testing.T) (*spcovEnv, *int) {
		e := aqSetup(t)
		s := newAQServer(t, e)
		s.respond = func(query *AttributeQuery) []byte {
			return e.aqSOAP(t, query, aqOptions{signAssertion: true})
		}
		plain, hits := plainHTTPServer(t, s.Config.Handler)
		e.sp.IDPMetadata.AttributeAuthorityDescriptors[0].AttributeServices[0].Location = plain.URL
		e.sp.HTTPClient = plain.Client()
		return e, hits
	}

	t.Run("refused", func(t *testing.T) {
		e, hits := setup(t)
		_, err := e.sp.MakeAttributeQuery(aqNameID)
		assert.Check(t, is.ErrorIs(err, ErrInsecureSOAPEndpoint))
		_, err = e.sp.QueryAttributes(context.Background(), aqNameID)
		assert.Check(t, is.ErrorIs(err, ErrInsecureSOAPEndpoint))
		assert.Check(t, is.Equal(*hits, 0))
	})
	t.Run("allowed", func(t *testing.T) {
		e, hits := setup(t)
		e.sp.AllowInsecureSOAPEndpoints = true
		result, err := e.sp.QueryAttributes(context.Background(), aqNameID)
		assert.NilError(t, err)
		assert.Check(t, len(result.Attributes) > 0)
		assert.Check(t, is.Equal(*hits, 1))
	})
}

// The service provider resolves artifacts only at an https
// ArtifactResolutionService, unless AllowInsecureSOAPEndpoints is set: the
// ArtifactResponse carries the whole assertion.
func TestArtifactResolutionRequiresHTTPS(t *testing.T) {
	setup := func(t *testing.T) (*spcovEnv, *int) {
		e := spcovSetup(t)
		plain, hits := plainHTTPServer(t, e.artifactHandler(t))
		e.sp.IDPMetadata.IDPSSODescriptors[0].ArtifactResolutionServices[0].Location = plain.URL + "/artifact"
		e.sp.HTTPClient = plain.Client()
		return e, hits
	}

	t.Run("refused", func(t *testing.T) {
		e, hits := setup(t)
		_, err := e.sp.ParseResponse(spcovArtifactRequest("the-artifact"), []string{spcovRequestID})
		privateErr := spcovPrivateErr(t, err)
		assert.Check(t, is.ErrorIs(privateErr, ErrInsecureSOAPEndpoint))
		assert.Check(t, is.ErrorIs(privateErr, ErrArtifactResolution))
		assert.Check(t, is.Equal(*hits, 0))
	})
	t.Run("allowed", func(t *testing.T) {
		e, hits := setup(t)
		e.sp.AllowInsecureSOAPEndpoints = true
		assertion, err := e.sp.ParseResponse(spcovArtifactRequest("the-artifact"), []string{spcovRequestID})
		assert.NilError(t, err)
		assert.Check(t, is.Equal(assertion.Subject.NameID.Value, "alice@example.com"))
		assert.Check(t, is.Equal(*hits, 1))
	})
}
