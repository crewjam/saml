package saml

import (
	"errors"
	"testing"
	"time"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// A Response or Assertion dated further in the future than MaxClockSkew is
// refused, as LogoutRequests and LogoutResponses already were; otherwise its
// IssueInstant would bound nothing.
func TestSPRefusesFutureIssueInstant(t *testing.T) {
	future := spcovNow.Add(MaxClockSkew + time.Second)
	withinSkew := spcovNow.Add(MaxClockSkew - time.Second)

	parse := func(t *testing.T, responseInstant, assertionInstant time.Time) error {
		t.Helper()
		e := spcovSetup(t)
		r := e.response()
		r.IssueInstant = responseInstant
		r.Assertion = e.assertion()
		r.Assertion.IssueInstant = assertionInstant
		_, err := e.sp.ParseXMLResponse(spcovSerialize(t, e.idpSign(t, r.Element())), []string{spcovRequestID}, e.sp.AcsURL)
		return err
	}

	t.Run("Response", func(t *testing.T) {
		err := parse(t, future, spcovNow)
		assert.Check(t, errors.Is(err, ErrNotYetValid), "%v", err)
		assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), "response IssueInstant"))
	})
	t.Run("Assertion", func(t *testing.T) {
		err := parse(t, spcovNow, future)
		assert.Check(t, errors.Is(err, ErrNotYetValid), "%v", err)
		assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), "assertion IssueInstant"))
	})
	t.Run("within skew", func(t *testing.T) {
		assert.NilError(t, parse(t, withinSkew, withinSkew))
	})
}

func TestArtifactResponseRefusesFutureIssueInstant(t *testing.T) {
	e := spcovSetup(t)
	el := e.artifactResponseEl(t, "id-artifact-request", true, func(ar *ArtifactResponse) {
		ar.IssueInstant = spcovNow.Add(MaxClockSkew + time.Second)
	})
	_, err := e.sp.ParseXMLArtifactResponse(spcovSerialize(t, spcovSOAPEnvelope(el)), []string{spcovRequestID}, "id-artifact-request", e.sp.AcsURL)
	assert.Check(t, errors.Is(err, ErrNotYetValid), "%v", err)
}

func TestAttributeQueryRefusesFutureIssueInstant(t *testing.T) {
	future := spcovNow.Add(MaxClockSkew + time.Second)
	for name, o := range map[string]aqOptions{
		"response":  {signResponse: true, response: func(r *Response) { r.IssueInstant = future }},
		"assertion": {signResponse: true, assertion: func(a *Assertion) { a.IssueInstant = future }},
	} {
		t.Run(name, func(t *testing.T) {
			e := aqSetup(t)
			query := e.aqQuery(t)
			_, err := e.sp.ParseXMLAttributeQueryResponse(e.aqSOAP(t, query, o), query)
			assert.Check(t, errors.Is(err, ErrNotYetValid), "%v", err)
		})
	}
}
