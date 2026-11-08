package saml

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/beevik/etree"

	"github.com/crewjam/saml/internal/signerutil"
)

// This file implements the requester side of the SAML Assertion Query and
// Request profile (saml-profiles §6) for attribute queries (saml-core
// §3.3.2.3) over the SAML SOAP binding (saml-bindings §3.2).

// MaxAttributeQueryResponseSize is the largest SOAP response body, in bytes,
// that QueryAttributes reads from the attribute authority. A larger response
// is rejected without being parsed.
var MaxAttributeQueryResponseSize int64 = 10 << 20

// ErrNoAttributeService is returned when the IdP metadata does not publish
// an AttributeService endpoint (in an AttributeAuthorityDescriptor) with the
// SAML SOAP binding, so there is nowhere to send an attribute query.
var ErrNoAttributeService = errors.New("the IdP metadata has no AttributeAuthorityDescriptor with a SOAP AttributeService")

// soapActionSAML is the SOAPAction a SAML requester may send with the SOAP
// binding (saml-bindings §3.2.2.1).
const soapActionSAML = "http://www.oasis-open.org/committees/security"

// AttributeQueryResult holds what an attribute authority returned for an
// attribute query, after it has been validated.
//
// It describes the subject named in the query. It is not evidence that the
// subject is present or authenticated, and must never be used to start a
// session.
type AttributeQueryResult struct {
	// Assertions are the validated assertions of the response, decrypted
	// where they were encrypted.
	Assertions []Assertion

	// Attributes are the attributes of every AttributeStatement of every
	// assertion, in document order.
	Attributes []Attribute
}

// GetAttributeServiceLocation returns the URL of the IdP's AttributeService
// endpoint with the given binding, from the AttributeAuthorityDescriptors of
// the IdP metadata, or "" if there is none. Attribute queries use
// SOAPBinding.
func (sp *ServiceProvider) GetAttributeServiceLocation(binding string) string {
	if sp.IDPMetadata == nil {
		return ""
	}
	for _, attributeAuthority := range sp.IDPMetadata.AttributeAuthorityDescriptors {
		for _, attributeService := range attributeAuthority.AttributeServices {
			if attributeService.Binding == binding {
				return attributeService.Location
			}
		}
	}
	return ""
}

// MakeAttributeQuery returns an AttributeQuery for the attributes of the
// subject identified by nameID, addressed to the IdP's SOAP AttributeService
// (see GetAttributeServiceLocation). It returns ErrNoAttributeService if the
// IdP metadata has none, and an error matching ErrInsecureSOAPEndpoint if
// its Location is not https and AllowInsecureSOAPEndpoints is not set.
//
// nameID is sent as is. Pass the NameID the IdP issued for the subject, for
// example Assertion.Subject.NameID from the login, so that its Format and
// qualifiers match what the IdP knows the subject by.
//
// attributes, if any, restricts the query to those attributes (and, for an
// Attribute that has Values, to those values). Each attribute may be named
// only once (saml-core §3.3.2.3). If attributes is empty, the IdP returns
// every attribute it releases to this service provider.
//
// The query is signed with SignAttributeQuery when Key is set, whether or not
// SignatureMethod is: attribute authorities usually release attributes only to
// requesters they can authenticate (saml-profiles §6.3.1). Without Key the
// query is unsigned, and the requester must be authenticated some other way,
// such as with a TLS client certificate in HTTPClient. The SP metadata
// publishes the certificate for signing only when SignatureMethod or
// LogoutSignatureMethod is set or SOAP single logout is offered; set one of
// them so that the attribute authority can verify the query.
func (sp *ServiceProvider) MakeAttributeQuery(nameID NameID, attributes ...Attribute) (*AttributeQuery, error) {
	if sp.IDPMetadata == nil {
		return nil, errors.New("cannot make an attribute query: IDPMetadata is not set")
	}
	destination := sp.GetAttributeServiceLocation(SOAPBinding)
	if destination == "" {
		return nil, ErrNoAttributeService
	}
	if err := checkSOAPEndpoint(destination, sp.AllowInsecureSOAPEndpoints); err != nil {
		return nil, fmt.Errorf("cannot make an attribute query: %w", err)
	}
	if nameID.Value == "" {
		return nil, errors.New("cannot make an attribute query: the NameID is empty")
	}
	if err := checkRequestedAttributesUnique(attributes); err != nil {
		return nil, err
	}

	query := &AttributeQuery{
		ID:           fmt.Sprintf("id-%x", randomBytes(20)),
		Version:      "2.0",
		IssueInstant: sp.now(),
		Destination:  destination,
		Issuer: &Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  sp.entityID(),
		},
		Subject:    &Subject{NameID: &nameID},
		Attributes: attributes,
	}
	if !signerutil.IsNil(sp.Key) {
		if err := sp.SignAttributeQuery(query); err != nil {
			return nil, err
		}
	}
	return query, nil
}

// checkRequestedAttributesUnique returns an error if two of attributes have
// the same Name and NameFormat, which saml-core §3.3.2.3 forbids.
func checkRequestedAttributesUnique(attributes []Attribute) error {
	type key struct{ name, nameFormat string }
	seen := make(map[key]bool, len(attributes))
	for _, attribute := range attributes {
		if attribute.Name == "" {
			return errors.New("cannot make an attribute query: a requested attribute has no Name")
		}
		k := key{attribute.Name, attribute.NameFormat}
		if seen[k] {
			return fmt.Errorf("cannot make an attribute query: attribute %q is requested more than once", attribute.Name)
		}
		seen[k] = true
	}
	return nil
}

// SignAttributeQuery adds an enveloped `Signature` element to the
// `AttributeQuery`, replacing any it already has. It signs with
// SignatureMethod or, when that is empty, with SHA-256 for the type of Key.
func (sp *ServiceProvider) SignAttributeQuery(req *AttributeQuery) error {
	signatureMethod := sp.SignatureMethod
	if signatureMethod == "" && !signerutil.IsNil(sp.Key) {
		signatureMethod = defaultSignatureMethod(sp.Key.Public())
	}
	signingContext, err := sp.signingContext(signatureMethod)
	if err != nil {
		return err
	}

	req.Signature = nil
	signedRequestEl, err := signingContext.SignEnveloped(req.Element())
	if err != nil {
		return err
	}
	sigEl, ok := signedRequestEl.Child[len(signedRequestEl.Child)-1].(*etree.Element)
	if !ok {
		return errors.New("cannot sign attribute query: no Signature element")
	}
	req.Signature = sigEl
	return nil
}

// QueryAttributes asks the IdP's attribute authority for the attributes of
// the subject identified by nameID, and returns them once the response has
// been validated with ParseXMLAttributeQueryResponse.
//
// The query is made with MakeAttributeQuery and sent with the SAML SOAP
// binding to the IdP's SOAP AttributeService, using HTTPClient (see
// ServiceProvider.HTTPClient) and ctx. The response body is limited to
// MaxAttributeQueryResponseSize bytes. The AttributeService must be https
// unless AllowInsecureSOAPEndpoints is set.
//
// Errors in making or sending the query are returned as they are; an invalid
// response is returned as an *InvalidResponseError.
func (sp *ServiceProvider) QueryAttributes(ctx context.Context, nameID NameID, attributes ...Attribute) (*AttributeQueryResult, error) {
	query, err := sp.MakeAttributeQuery(nameID, attributes...)
	if err != nil {
		return nil, err
	}
	responseBody, err := sp.postSOAP(ctx, query.Destination, query.SoapRequest(), MaxAttributeQueryResponseSize)
	if err != nil {
		return nil, fmt.Errorf("attribute query to %s: %w", query.Destination, err)
	}
	return sp.ParseXMLAttributeQueryResponse(responseBody, query)
}

// postSOAP sends envelope to location with the SAML SOAP binding, using
// HTTPClient (see ServiceProvider.HTTPClient), and returns the body of the response,
// which may be at most limit bytes. location must be https unless
// AllowInsecureSOAPEndpoints is set.
func (sp *ServiceProvider) postSOAP(ctx context.Context, location string, envelope *etree.Element, limit int64) ([]byte, error) {
	if err := checkSOAPEndpoint(location, sp.AllowInsecureSOAPEndpoints); err != nil {
		return nil, err
	}
	httpClient := soapHTTPClient(sp.HTTPClient, sp.AllowInsecureSOAPEndpoints)
	return postSOAPMessage(ctx, httpClient, location, envelope, limit)
}

// ParseXMLAttributeQueryResponse validates soapResponseXML, the SOAP
// envelope an attribute authority returned for query, and returns the
// attributes it carries. Use it to send query with your own transport;
// QueryAttributes calls it for you.
//
// The SOAP Body must hold exactly one samlp:Response, which must:
//
//   - be InResponseTo query.ID, and recently issued;
//   - have Issuer equal to the IdP entity ID; Issuer may be omitted only
//     when the Response is not signed;
//   - have a Success status, or else an ErrBadStatus is returned;
//   - either carry a valid signature by the IdP, or have every assertion
//     signed by the IdP, in which case it must have at least one assertion;
//   - have no Destination, or the entity ID of this service provider. A
//     response that comes back over the synchronous SOAP binding is not
//     delivered to an endpoint of the service provider, so there is no URL it
//     can be checked against; Destination is optional (saml-core §3.2.2), and
//     a Destination naming anything else means it was meant for someone else.
//
// Signatures are verified with the signing keys of the IdP's
// AttributeAuthorityDescriptor, or, if it publishes none, those of its
// IDPSSODescriptor (or IDPCertificate or IDPCertificateFingerprint, if set).
//
// EncryptedAssertions, and EncryptedIDs in place of a Subject NameID, are
// decrypted as for login (and, with RequireSignedResponseForCBC, one
// encrypted in CBC mode only in a signed Response). Every assertion must be
// valid, or the response is rejected:
//
//   - its Issuer is the IdP entity ID, and it was recently issued;
//   - its Subject has a NameID identical to the one of query (saml-core
//     §3.3.4), where an omitted Format means unspecified, and an omitted
//     NameQualifier or SPNameQualifier means the IdP or this service
//     provider;
//   - it has Conditions that are currently valid and an AudienceRestriction
//     naming this service provider (or passes ValidateAudienceRestriction),
//     and, with RejectUnknownConditions, no condition this package does not
//     understand (or passes ValidateUnknownConditions);
//   - any SubjectConfirmationData is currently valid, and, if it has an
//     InResponseTo, is InResponseTo query.ID.
//
// Unlike login, no bearer SubjectConfirmation is required, and its Method
// and Recipient are not checked: attribute authorities typically use the
// sender-vouches method or none, and the assertion came straight from the
// IdP over a connection the service provider opened, rather than from a
// presenter who would have to be confirmed. This is why the result describes
// the subject but never authenticates it.
//
// If ReplayCache is set, each assertion's ID is recorded in it, and an
// assertion it has seen before is rejected.
//
// If the function fails it returns an *InvalidResponseError whose
// PrivateErr says what was wrong.
func (sp *ServiceProvider) ParseXMLAttributeQueryResponse(soapResponseXML []byte, query *AttributeQuery) (*AttributeQueryResult, error) {
	now := sp.now()
	result, err := sp.parseAttributeQueryResponse(soapResponseXML, query, now)
	if err != nil {
		return nil, &InvalidResponseError{
			PrivateErr: err,
			Response:   string(soapResponseXML),
			Now:        now,
		}
	}
	return result, nil
}

func (sp *ServiceProvider) parseAttributeQueryResponse(soapResponseXML []byte, query *AttributeQuery, now time.Time) (*AttributeQueryResult, error) {
	if query == nil || query.ID == "" || query.Subject == nil || query.Subject.NameID == nil {
		return nil, classify(errors.New("the attribute query has no ID or no Subject NameID"), ErrMissingElement)
	}
	if sp.IDPMetadata == nil {
		return nil, errors.New("IDPMetadata is not set")
	}

	responseEl, err := soapResponseElement(soapResponseXML)
	if err != nil {
		return nil, err
	}

	receivedResponseEl := responseEl
	signedResponseEl, responseSigned, err := sp.attributeQuerySignature(responseEl)
	if err != nil {
		return nil, err
	}
	if responseSigned {
		// Read the Response, and its assertions, from what the signature covers.
		responseEl = signedResponseEl
	}

	var response Response
	if err := unmarshalElement(responseEl, &response); err != nil {
		return nil, classify(fmt.Errorf("cannot unmarshal response: %w", err), ErrMalformedMessage)
	}
	if err := sp.validateAttributeQueryResponse(&response, query, responseSigned, now); err != nil {
		return nil, err
	}

	assertions, err := sp.attributeQueryAssertions(responseEl, receivedResponseEl, query, now, !responseSigned)
	if err != nil {
		return nil, err
	}
	if len(assertions) == 0 && !responseSigned {
		return nil, errors.New("the Response is not signed and has no Assertion")
	}

	for i := range assertions {
		if err := sp.consumeAssertion(&assertions[i]); err != nil {
			return nil, err
		}
	}

	result := &AttributeQueryResult{Assertions: assertions}
	for _, assertion := range assertions {
		for _, attributeStatement := range assertion.AttributeStatements {
			result.Attributes = append(result.Attributes, attributeStatement.Attributes...)
		}
	}
	return result, nil
}

// soapResponseElement parses soapResponseXML as a SOAP 1.1 envelope and
// returns the samlp:Response that must be the only element of its Body.
func soapResponseElement(soapResponseXML []byte) (*etree.Element, error) {
	return soapBodyElement(soapResponseXML, "Response")
}

// attributeAuthoritySigningCerts returns the IdP certificates that may sign
// attribute query responses: those of its AttributeAuthorityDescriptors, or
// if they have none, those of its IDPSSODescriptors.
func (sp *ServiceProvider) attributeAuthoritySigningCerts() ([]*x509.Certificate, error) {
	if err := sp.checkIDPMetadataNotExpired(); err != nil {
		return nil, err
	}
	var keyDescriptors []KeyDescriptor
	for i, attributeAuthority := range sp.IDPMetadata.AttributeAuthorityDescriptors {
		if err := sp.checkRoleNotExpired(&sp.IDPMetadata.AttributeAuthorityDescriptors[i].RoleDescriptor, "AttributeAuthorityDescriptor"); err != nil {
			return nil, err
		}
		keyDescriptors = append(keyDescriptors, attributeAuthority.KeyDescriptors...)
	}
	certs, err := signingCerts(keyDescriptors)
	if err != nil {
		return nil, err
	}
	if len(certs) > 0 {
		return certs, nil
	}
	return sp.getIDPSigningCerts()
}

// attributeQuerySignature reports whether el carries a valid signature by
// the attribute authority and, if so, returns what the signature covers
// (see validatedElement). A signature that is present but not valid is an
// error.
func (sp *ServiceProvider) attributeQuerySignature(el *etree.Element) (*etree.Element, bool, error) {
	signed, err := sp.verifySignedElement(el, sp.attributeAuthoritySigningCerts)
	switch err {
	case nil:
		return signed, true, nil
	case errSignatureElementNotPresent:
		return nil, false, nil
	default:
		return nil, false, err
	}
}

// validateAttributeQueryResponse checks the Response to query, apart from
// its signature and assertions.
func (sp *ServiceProvider) validateAttributeQueryResponse(response *Response, query *AttributeQuery, signed bool, now time.Time) error {
	if err := checkVersion("response", response.Version); err != nil {
		return err
	}
	if response.InResponseTo != query.ID {
		return classify(fmt.Errorf("`InResponseTo` %q does not match the attribute query ID %q", response.InResponseTo, query.ID), ErrRequestIDMismatch)
	}
	if err := sp.limits().checkIssueInstant("response IssueInstant", response.IssueInstant, now); err != nil {
		return err
	}
	if response.Issuer == nil {
		if signed {
			return classify(errors.New("the signed Response has no Issuer"), ErrMissingElement)
		}
	} else if response.Issuer.Value != sp.IDPMetadata.EntityID {
		return classify(fmt.Errorf("response Issuer does not match the IDP metadata (expected %q)", sp.IDPMetadata.EntityID), ErrIssuerMismatch)
	}
	if response.Destination != "" && response.Destination != sp.entityID() {
		return classify(fmt.Errorf("`Destination` %q is not this service provider (%q)", response.Destination, sp.entityID()), ErrDestinationMismatch)
	}
	return statusError(response.Status)
}

// statusError returns nil for a Success status, and otherwise the
// ErrBadStatus that reports it.
func statusError(status Status) error {
	if status.StatusCode.Value == StatusSuccess {
		return nil
	}
	return newErrBadStatus(status)
}

// attributeQueryAssertions returns the assertions of responseEl, decrypting
// the encrypted ones. Each must be valid for query; if signatureRequired,
// each must also be signed by the attribute authority. receivedEl is the
// Response as received (see receivedChildren), on whose plaintext
// assertions their signatures are checked.
func (sp *ServiceProvider) attributeQueryAssertions(responseEl, receivedEl *etree.Element, query *AttributeQuery, now time.Time, signatureRequired bool) ([]Assertion, error) {
	var assertionEls []*etree.Element

	encryptedAssertionEls, err := findChildren(responseEl, "urn:oasis:names:tc:SAML:2.0:assertion", "EncryptedAssertion")
	if err != nil {
		return nil, err
	}
	plaintextAssertionEls, receivedAssertionEls, err := receivedChildren(responseEl, receivedEl, "urn:oasis:names:tc:SAML:2.0:assertion", "Assertion")
	if err != nil {
		return nil, err
	}

	// As for a login response: each assertion of an unsigned Response is
	// decrypted and its signature checked, which costs more per assertion,
	// so an unsigned Response may carry only one. Count before decrypting.
	if signatureRequired {
		if n := len(encryptedAssertionEls) + len(plaintextAssertionEls); n > 1 {
			return nil, classify(fmt.Errorf("an unsigned Response must contain exactly one Assertion or EncryptedAssertion, not %d", n), ErrMalformedMessage)
		}
	}

	for _, encryptedAssertionEl := range encryptedAssertionEls {
		if err := sp.checkCBCIntegrity(encryptedAssertionEl, !signatureRequired); err != nil {
			return nil, err
		}
		assertionEl, err := sp.decryptElement(encryptedAssertionEl)
		if err != nil {
			return nil, classify(fmt.Errorf("failed to decrypt EncryptedAssertion: %w", err), ErrDecryptionFailed)
		}
		if assertionEl.NamespaceURI() != "urn:oasis:names:tc:SAML:2.0:assertion" || assertionEl.Tag != "Assertion" {
			return nil, classify(errors.New("the EncryptedAssertion does not hold an Assertion"), ErrMalformedMessage)
		}
		assertionEls = append(assertionEls, assertionEl)
	}
	// A decrypted assertion is its own received form.
	receivedEls := append(append([]*etree.Element{}, assertionEls...), receivedAssertionEls...)
	assertionEls = append(assertionEls, plaintextAssertionEls...)

	assertions := make([]Assertion, 0, len(assertionEls))
	for i, assertionEl := range assertionEls {
		assertion, err := sp.attributeQueryAssertion(assertionEl, receivedEls[i], query, now, signatureRequired)
		if err != nil {
			return nil, err
		}
		assertions = append(assertions, *assertion)
	}
	return assertions, nil
}

// attributeQueryAssertion parses and validates assertionEl. receivedEl is
// the assertion as received (see receivedChildren), on which its signature
// is checked.
func (sp *ServiceProvider) attributeQueryAssertion(assertionEl, receivedEl *etree.Element, query *AttributeQuery, now time.Time, signatureRequired bool) (*Assertion, error) {
	// A signature that is present must be valid even when the Response is
	// signed (saml-core §2.3.3).
	signed, err := sp.verifySignedElement(receivedEl, sp.attributeAuthoritySigningCerts)
	switch err {
	case nil:
		// Read the assertion from what the signature covers.
		assertionEl = signed
	case errSignatureElementNotPresent:
		if signatureRequired {
			return nil, errors.New("neither the Response nor its Assertion is signed")
		}
	default:
		return nil, err
	}
	var assertion Assertion
	if err := unmarshalElement(assertionEl, &assertion); err != nil {
		return nil, err
	}
	if err := fillAttributeValuesXML(assertionEl, &assertion); err != nil {
		return nil, err
	}
	if err := sp.decryptEncryptedIDs(assertion.Subject); err != nil {
		return nil, fmt.Errorf("assertion %q: %w", assertion.ID, err)
	}
	if err := sp.decryptEncryptedAttributes(assertionEl, &assertion); err != nil {
		return nil, fmt.Errorf("assertion %q: %w", assertion.ID, err)
	}
	if err := sp.validateAttributeQueryAssertion(&assertion, query, now); err != nil {
		return nil, fmt.Errorf("assertion %q: %w", assertion.ID, err)
	}
	return &assertion, nil
}

// validateAttributeQueryAssertion checks assertion, apart from its signature,
// as an answer to query. Unlike validateAssertion, it does not require a
// bearer SubjectConfirmation; see ParseXMLAttributeQueryResponse.
func (sp *ServiceProvider) validateAttributeQueryAssertion(assertion *Assertion, query *AttributeQuery, now time.Time) error {
	if err := checkVersion("assertion", assertion.Version); err != nil {
		return err
	}
	if sp.limits().issueDeadline(assertion).Before(now) {
		return classify(fmt.Errorf("expired on %s", sp.limits().issueDeadline(assertion)), ErrExpired)
	}
	if assertion.IssueInstant.Add(-sp.maxClockSkew()).After(now) {
		return classify(fmt.Errorf("assertion IssueInstant %s is in the future", assertion.IssueInstant), ErrNotYetValid)
	}
	if assertion.Issuer.Value != sp.IDPMetadata.EntityID {
		return classify(fmt.Errorf("issuer is not %q", sp.IDPMetadata.EntityID), ErrIssuerMismatch)
	}
	if assertion.Subject == nil || assertion.Subject.NameID == nil {
		return classify(errors.New("assertion has no Subject NameID"), ErrMissingElement)
	}
	if !sp.nameIDsIdentical(query.Subject.NameID, assertion.Subject.NameID) {
		return fmt.Errorf("assertion Subject NameID %q does not match the queried NameID %q",
			assertion.Subject.NameID.Value, query.Subject.NameID.Value)
	}
	if err := validateQuerySubjectConfirmations(assertion.Subject, query.ID, now, sp.limits()); err != nil {
		return err
	}
	if assertion.Conditions == nil {
		return classify(errors.New("assertion has no Conditions"), ErrMissingElement)
	}
	if assertion.Conditions.NotBefore.Add(-sp.maxClockSkew()).After(now) {
		return classify(errors.New("assertion Conditions is not yet valid"), ErrNotYetValid)
	}
	if !assertion.Conditions.NotOnOrAfter.IsZero() && sp.limits().pastDeadline(assertion.Conditions.NotOnOrAfter, now) {
		return classify(errors.New("assertion Conditions is expired"), ErrExpired)
	}
	if err := sp.validateUnknownConditions(assertion); err != nil {
		return err
	}
	return sp.validateAudienceRestriction(assertion)
}

// validateQuerySubjectConfirmations checks the SubjectConfirmationData of
// subject, if any, against the time and the ID of the attribute query.
func validateQuerySubjectConfirmations(subject *Subject, queryID string, now time.Time, l timeLimits) error {
	for _, subjectConfirmation := range subject.SubjectConfirmations {
		data := subjectConfirmation.SubjectConfirmationData
		if data == nil {
			continue
		}
		if data.InResponseTo != "" && data.InResponseTo != queryID {
			return classify(fmt.Errorf("assertion SubjectConfirmationData InResponseTo %q is not the attribute query ID", data.InResponseTo), ErrRequestIDMismatch)
		}
		if data.NotBefore.Add(-l.skew()).After(now) {
			return classify(errors.New("assertion SubjectConfirmationData is not yet valid"), ErrNotYetValid)
		}
		if !data.NotOnOrAfter.IsZero() && l.pastDeadline(data.NotOnOrAfter, now) {
			return classify(errors.New("assertion SubjectConfirmationData is expired"), ErrExpired)
		}
	}
	return nil
}

// nameIDsIdentical reports whether got is identical to want, as saml-core
// §3.3.4 requires of the subject of an assertion answering a query. An
// omitted Format is the unspecified format (§8.3.1), and an omitted
// NameQualifier or SPNameQualifier is the IdP or this service provider
// (§2.2.2), so that an IdP may spell out a default the query left implicit.
func (sp *ServiceProvider) nameIDsIdentical(want, got *NameID) bool {
	format := func(f string) string { return firstSet(f, string(UnspecifiedNameIDFormat)) }
	nameQualifier := func(q string) string { return firstSet(q, sp.IDPMetadata.EntityID) }
	spNameQualifier := func(q string) string { return firstSet(q, sp.entityID()) }
	return got.Value == want.Value &&
		format(got.Format) == format(want.Format) &&
		nameQualifier(got.NameQualifier) == nameQualifier(want.NameQualifier) &&
		spNameQualifier(got.SPNameQualifier) == spNameQualifier(want.SPNameQualifier) &&
		got.SPProvidedID == want.SPProvidedID
}

// entityID is the entity ID of this service provider.
func (sp *ServiceProvider) entityID() string {
	return firstSet(sp.EntityID, sp.MetadataURL.String())
}
