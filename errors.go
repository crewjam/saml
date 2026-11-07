package saml

import (
	"crypto/x509"
	"errors"
	"time"

	"github.com/beevik/etree"
)

// Errors that the ServiceProvider attaches to signature validation failures,
// so that callers can tell them apart with errors.Is instead of matching
// error strings. They are reachable through the *InvalidResponseError that
// ParseResponse and ParseXMLResponse return:
//
//	assertion, err := sp.ParseResponse(r, requestIDs)
//	if errors.Is(err, saml.ErrUntrustedCertificate) {
//		// the IdP signed with a certificate that is not in its metadata;
//		// the metadata may be out of date
//	}
//
// The message of the error returned is unchanged by this classification.
var (
	// ErrInvalidSignature is attached to every failure to validate the XML
	// signature on a Response, Assertion or ArtifactResponse. The more
	// specific errors below are attached in addition to it.
	ErrInvalidSignature = errors.New("saml: invalid signature")

	// ErrUntrustedCertificate is attached when the element is signed with a
	// certificate that is not one of the trusted IdP certificates (from the
	// IdP metadata, ServiceProvider.IDPCertificate, or the configured
	// fingerprint). This commonly means the IdP rotated its signing
	// certificate and the IdP metadata held by the SP needs to be updated.
	ErrUntrustedCertificate = errors.New("saml: signing certificate is not trusted")

	// ErrCertificateNotValidNow is attached when the element is signed with
	// a trusted certificate that is expired or not yet valid. See
	// ServiceProvider.IgnoreCertificateExpiry.
	ErrCertificateNotValidNow = errors.New("saml: signing certificate is expired or not yet valid")
)

// Errors attached to the other reasons a message is rejected: by the
// ServiceProvider for a Response, Assertion, ArtifactResponse, LogoutResponse
// or LogoutRequest, and by the IdentityProvider for an AuthnRequest (from
// NewIdpAuthnRequest and IdpAuthnRequest.Validate). Like the signature errors
// above, they are matched with errors.Is, through *InvalidResponseError where
// one is returned, and leave the message of the error unchanged.
//
// A rejected logout response whose status is not success also matches
// ErrBadStatus with errors.As, as a rejected Response already does.
var (
	// ErrMalformedMessage is attached when a message cannot be decoded or
	// parsed: bad base64, deflate or form encoding, invalid XML, a missing root
	// element, an element that cannot be unmarshalled, or more instances of
	// an element than allowed.
	ErrMalformedMessage = errors.New("saml: malformed message")

	// ErrMissingElement is attached when a required element or value is
	// absent: no Assertion, an Assertion with no Subject, Conditions, ID,
	// AuthnStatement, SubjectConfirmationData or bearer SubjectConfirmation,
	// a LogoutRequest with no NameID, an AuthnRequest with no Issuer or ID,
	// or another required child element.
	ErrMissingElement = errors.New("saml: required element is missing")

	// ErrExpired is attached when a message or assertion is no longer valid:
	// its IssueInstant is older than MaxIssueDelay, or a NotOnOrAfter
	// (allowing MaxClockSkew) has passed. Check the clocks of the IdP and
	// SP if this happens for fresh logins.
	ErrExpired = errors.New("saml: expired")

	// ErrNotYetValid is attached when a message or assertion is not valid
	// yet: a Conditions or SubjectConfirmationData NotBefore (allowing
	// MaxClockSkew) or a LogoutRequest IssueInstant in the future. This usually means the IdP and SP clocks
	// disagree.
	ErrNotYetValid = errors.New("saml: not yet valid")

	// ErrIssuerMismatch is attached when the Issuer of a message or
	// assertion is not the EntityID in the IdP metadata.
	ErrIssuerMismatch = errors.New("saml: issuer does not match the IdP metadata")

	// ErrDestinationMismatch is attached when a message was not addressed to
	// its recipient. At the SP: a Destination that is neither the requested
	// URL nor AcsURL (or SloURL, for logout messages), or a
	// SubjectConfirmationData Recipient that is not AcsURL. At the IdP: an
	// AuthnRequest Destination that is not IdentityProvider.SSOURL.
	ErrDestinationMismatch = errors.New("saml: destination does not match the recipient")

	// ErrRequestIDMismatch is attached when an InResponseTo does not name
	// one of the requests this SP made (possibleRequestIDs), or the artifact
	// request ID for an ArtifactResponse.
	ErrRequestIDMismatch = errors.New("saml: InResponseTo does not match a request ID")

	// ErrAudienceMismatch is attached when the assertion is not restricted
	// to this SP's audience, or ServiceProvider.ValidateAudienceRestriction
	// rejects it.
	ErrAudienceMismatch = errors.New("saml: audience restriction does not match this service provider")

	// ErrAuthnContextMismatch is attached when
	// ServiceProvider.ValidateAuthnContextClassRef is set and none of the
	// assertion's AuthnContextClassRefs is one of those in
	// ServiceProvider.RequestedAuthnContext (or, for a Comparison other than
	// "exact", none is accepted by AuthnContextClassRefComparator): the user
	// did not authenticate the way the SP asked.
	ErrAuthnContextMismatch = errors.New("saml: authentication context does not match the requested one")

	// ErrDecryptionFailed is attached when an EncryptedAssertion or
	// EncryptedID cannot be decrypted with the SP's keys.
	ErrDecryptionFailed = errors.New("saml: cannot decrypt")

	// ErrArtifactResolution is attached when resolving an artifact with the
	// IdP fails: building the request, the HTTP exchange, or a non-200
	// status.
	ErrArtifactResolution = errors.New("saml: artifact resolution failed")

	// ErrUnknownServiceProvider is attached when an AuthnRequest's Issuer is
	// not a service provider the IdP knows: its ServiceProviderProvider
	// returned os.ErrNotExist, which the error also matches.
	ErrUnknownServiceProvider = errors.New("saml: unknown service provider")

	// ErrUnknownAssertionConsumerService is attached when the
	// AssertionConsumerServiceURL or AssertionConsumerServiceIndex of an
	// AuthnRequest is not in the service provider's metadata, or the
	// metadata has no usable assertion consumer service. The SP metadata the
	// IdP holds may be out of date.
	ErrUnknownAssertionConsumerService = errors.New("saml: unknown assertion consumer service")

	// ErrUnsupported is attached when something is used that is not
	// implemented. At the IdP: an HTTP method other than GET or POST, a SAML
	// version other than 2.0, signed AuthnRequests (WantAuthnRequestsSigned),
	// or an assertion consumer service binding other than HTTP-POST. At the
	// SP: a Response, ArtifactResponse, assertion, LogoutRequest or
	// LogoutResponse whose Version is not 2.0, a RequestedAuthnContext
	// Comparison other than "exact" when
	// ValidateAuthnContextClassRef is set and AuthnContextClassRefComparator
	// is not, or an assertion whose Conditions has a condition this package
	// does not understand when ValidateUnknownConditions is not set.
	ErrUnsupported = errors.New("saml: not supported")

	// ErrRelayStateTooLong is returned, when ServiceProvider or
	// IdentityProvider LimitRelayStateLength is set, for a message this
	// package starts that would carry a RelayState longer than
	// MaxRelayStateLength: an AuthnRequest or LogoutRequest the SP sends, a
	// RelayState a samlsp RelayStateFunc returns, or the RelayState of an
	// IdP-initiated Response (ServeIDPInitiated answers HTTP 400).
	ErrRelayStateTooLong = errors.New("saml: RelayState too long")

	// ErrInvalidCertificate is attached when a certificate cannot be base64
	// decoded or parsed: an IdP signing certificate in the IdP metadata or
	// ServiceProvider.IDPCertificate, the certificate embedded in a
	// signature when checking ServiceProvider.IDPCertificateFingerprint, or
	// an SP encryption certificate in the SP metadata the IdP holds. At the
	// SP the error also matches ErrInvalidSignature.
	ErrInvalidCertificate = errors.New("saml: invalid certificate")
)

// Unwrap returns PrivateErr, so that errors.Is and errors.As can inspect the
// reason a response was rejected.
func (ivr *InvalidResponseError) Unwrap() error {
	return ivr.PrivateErr
}

// classifiedError keeps the message of err but also matches kinds with
// errors.Is, so that error values can be added without changing messages
// callers may already rely on.
type classifiedError struct {
	err   error
	kinds []error
}

func (e *classifiedError) Error() string { return e.err.Error() }

func (e *classifiedError) Unwrap() []error {
	return append([]error{e.err}, e.kinds...)
}

func classify(err error, kinds ...error) error {
	if err == nil {
		return nil
	}
	return &classifiedError{err: err, kinds: kinds}
}

// classifyCertificate reports whether a signature that failed to validate
// against roots was made with an untrusted certificate, or with a trusted
// one outside its validity period at now. It mirrors how goxmldsig picks the
// signing certificate: the first X509Certificate in the Signature's KeyInfo,
// or the only root when there is no KeyInfo. It returns nil when neither
// applies or the certificate cannot be determined.
func classifyCertificate(el *etree.Element, roots []*x509.Certificate, now time.Time) error {
	var signingCert *x509.Certificate
	if certEl := el.FindElement("./Signature/KeyInfo/X509Data/X509Certificate"); certEl != nil {
		cert, err := parseCert(certEl.Text())
		if err != nil {
			return nil
		}
		signingCert = cert
	} else if el.FindElement("./Signature/KeyInfo") == nil && len(roots) == 1 {
		signingCert = roots[0]
	} else {
		return nil
	}

	for _, root := range roots {
		if root.Equal(signingCert) {
			if now.Before(root.NotBefore) || now.After(root.NotAfter) {
				return ErrCertificateNotValidNow
			}
			return nil
		}
	}
	return ErrUntrustedCertificate
}
