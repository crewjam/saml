package saml

import (
	"errors"
	"testing"
	"time"

	"gotest.tools/v3/assert"
)

// Attribute query failures carry the same Err* classification as the
// login and logout paths, so that callers can use errors.Is.
func TestParseXMLAttributeQueryResponseClassifiesErrors(t *testing.T) {
	testCases := []struct {
		name string
		o    aqOptions
		want error
	}{
		{"wrong InResponseTo", aqOptions{signResponse: true, response: func(r *Response) { r.InResponseTo = "id-other" }}, ErrRequestIDMismatch},
		{"wrong response Issuer", aqOptions{signResponse: true, response: func(r *Response) { r.Issuer.Value = "https://evil.example.com" }}, ErrIssuerMismatch},
		{"signed response without Issuer", aqOptions{signResponse: true, response: func(r *Response) { r.Issuer = nil }}, ErrMissingElement},
		{"Destination of another party", aqOptions{signResponse: true, response: func(r *Response) { r.Destination = aqLocation }}, ErrDestinationMismatch},
		{"expired response", aqOptions{signResponse: true, response: func(r *Response) { r.IssueInstant = spcovNow.Add(-time.Hour) }}, ErrExpired},
		{"wrong assertion Issuer", aqOptions{signResponse: true, assertion: func(a *Assertion) { a.Issuer.Value = "https://evil.example.com" }}, ErrIssuerMismatch},
		{"no Conditions", aqOptions{signResponse: true, assertion: func(a *Assertion) { a.Conditions = nil }}, ErrMissingElement},
		{"expired Conditions", aqOptions{signResponse: true, assertion: func(a *Assertion) {
			a.Conditions.NotOnOrAfter = spcovNow.Add(-MaxClockSkew - time.Second)
		}}, ErrExpired},
		{"Conditions not yet valid", aqOptions{signResponse: true, assertion: func(a *Assertion) {
			a.Conditions.NotBefore = spcovNow.Add(MaxClockSkew + time.Second)
		}}, ErrNotYetValid},
		{"expired assertion", aqOptions{signResponse: true, assertion: func(a *Assertion) { a.IssueInstant = spcovNow.Add(-time.Hour) }}, ErrExpired},
		{"SubjectConfirmationData for another request", aqOptions{signResponse: true, assertion: func(a *Assertion) {
			a.Subject.SubjectConfirmations[0].SubjectConfirmationData = &SubjectConfirmationData{InResponseTo: "id-other"}
		}}, ErrRequestIDMismatch},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e := aqSetup(t)
			query := e.aqQuery(t)
			_, err := e.sp.ParseXMLAttributeQueryResponse(e.aqSOAP(t, query, tc.o), query)
			var ire *InvalidResponseError
			assert.Check(t, errors.As(err, &ire), "%T: %v", err, err)
			assert.Check(t, errors.Is(err, tc.want), "%v", spcovPrivateErr(t, err))
		})
	}
}
