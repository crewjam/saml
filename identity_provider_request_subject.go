package saml

// nameIDFormatUnspecified is the NameID Format that leaves the
// interpretation of the identifier to the implementation (saml-core
// §8.3.1). A request Subject with this Format matches a NameID of any
// Format with the same value.
const nameIDFormatUnspecified = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"

// CheckRequestSubject checks that the assertion the AssertionMaker put in
// req.Assertion is about the principal the AuthnRequest names in its
// <saml:Subject>, if it names one. saml-core §3.4.1.4 requires the resulting
// assertion's Subject to strongly match the request's (saml-core §3.3.4),
// and errata E75 and saml-profiles §4.1.4.1 require an identity provider
// that cannot or will not produce such an assertion to answer with an error
// <Status> and no assertion.
//
// It returns nil when the request has no Subject or there is no assertion
// yet, and otherwise a *StatusError, with the second-level status
// StatusUnknownPrincipal unless noted, when:
//
//   - the request Subject has no identifier, only SubjectConfirmation
//     elements: StatusRequester, since saml-core §3.3.4 requires an
//     identifier to match and the request is malformed for this profile;
//   - the request Subject identifies the principal with a BaseID or an
//     EncryptedID, which this package cannot compare, or the assertion's
//     Subject has no NameID to compare with: StatusResponder, since the
//     limitation is the identity provider's;
//   - the NameID values differ, or the request gives a Format (other than
//     unspecified), NameQualifier, SPNameQualifier or SPProvidedID that the
//     assertion's NameID does not have: StatusRequester, since the service
//     provider asked about a principal other than the one the identity
//     provider has authenticated, and the same request cannot succeed in
//     this session;
//   - the request Subject has SubjectConfirmation elements and the
//     assertion has none with any of their Methods: StatusResponder with
//     the second-level status StatusRequestUnsupported, since the identity
//     provider does not issue that kind of confirmation.
//
// ServeSSO calls it after the AssertionMaker and sends the error Response
// itself. A handler that calls the AssertionMaker directly should call it
// too, and send any error with IdentityProvider.SendErrorResponse.
func (req *IdpAuthnRequest) CheckRequestSubject() error {
	if statusErr := req.requestSubjectStatusError(); statusErr != nil {
		return statusErr
	}
	return nil
}

// requestSubjectStatusError returns the status CheckRequestSubject reports,
// or nil.
func (req *IdpAuthnRequest) requestSubjectStatusError() *StatusError {
	requested := req.Request.Subject
	if requested == nil || req.Assertion == nil {
		return nil
	}
	asserted := req.Assertion.Subject
	if statusErr := requestSubjectIdentifierStatusError(requested, asserted); statusErr != nil {
		return statusErr
	}
	if !nameIDMatchesRequest(requested.NameID, asserted.NameID) {
		return &StatusError{
			TopLevel:    StatusRequester,
			SecondLevel: StatusUnknownPrincipal,
			Message:     "the authenticated principal is not the subject of the request",
		}
	}
	if !subjectConfirmationsMatchRequest(requested.SubjectConfirmations, asserted.SubjectConfirmations) {
		return &StatusError{
			TopLevel:    StatusResponder,
			SecondLevel: StatusRequestUnsupported,
			Message:     "the requested subject confirmation method is not supported",
		}
	}
	return nil
}

// requestSubjectIdentifierStatusError returns the status for a request
// Subject whose identifier cannot be compared with the asserted Subject's,
// or nil if both have a NameID.
func requestSubjectIdentifierStatusError(requested, asserted *Subject) *StatusError {
	switch {
	case requested.BaseID != nil || requested.EncryptedID != nil:
		return &StatusError{
			TopLevel:    StatusResponder,
			SecondLevel: StatusUnknownPrincipal,
			Message:     "the request subject identifier is not supported",
		}
	case requested.NameID == nil:
		return &StatusError{
			TopLevel:    StatusRequester,
			SecondLevel: StatusUnknownPrincipal,
			Message:     "the request subject has no identifier",
		}
	case asserted == nil || asserted.NameID == nil:
		return &StatusError{
			TopLevel:    StatusResponder,
			SecondLevel: StatusUnknownPrincipal,
			Message:     "the subject of the request cannot be matched",
		}
	}
	return nil
}

// nameIDMatchesRequest reports whether the asserted NameID identifies the
// principal the requested one does: the values are equal, and so is each
// attribute the request gives, except a Format of unspecified.
func nameIDMatchesRequest(requested, asserted *NameID) bool {
	if requested.Value != asserted.Value {
		return false
	}
	if requested.Format != "" && requested.Format != nameIDFormatUnspecified &&
		requested.Format != asserted.Format {
		return false
	}
	return requestedAttrMatches(requested.NameQualifier, asserted.NameQualifier) &&
		requestedAttrMatches(requested.SPNameQualifier, asserted.SPNameQualifier) &&
		requestedAttrMatches(requested.SPProvidedID, asserted.SPProvidedID)
}

// requestedAttrMatches reports whether an attribute of the asserted NameID
// matches the requested one, which matches anything when it is empty.
func requestedAttrMatches(requested, asserted string) bool {
	return requested == "" || requested == asserted
}

// subjectConfirmationsMatchRequest reports whether the asserted Subject can
// be confirmed in a manner one of the requested SubjectConfirmations
// describes (saml-core §3.3.4), comparing their Methods. A request with no
// SubjectConfirmation matches any assertion.
func subjectConfirmationsMatchRequest(requested, asserted []SubjectConfirmation) bool {
	if len(requested) == 0 {
		return true
	}
	for _, r := range requested {
		for _, a := range asserted {
			if r.Method == a.Method {
				return true
			}
		}
	}
	return false
}
