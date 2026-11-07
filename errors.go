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
