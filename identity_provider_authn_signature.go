package saml

import (
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/beevik/etree"
)

// errAuthnRequestNotSigned is returned, matching ErrInvalidSignature, for an
// unsigned AuthnRequest that must be signed.
var errAuthnRequestNotSigned = errors.New("authn request is not signed")

// verifySignature checks the signature of the request, whichever binding
// carried it, against the signing certificates in the service provider's
// metadata, and refuses an unsigned request that must be signed (see
// Validate). ServiceProviderMetadata must be set.
//
// When the request has an enveloped XML signature, Request is read again
// from what the signature covers, its Issuer must still be the service
// provider whose keys verified it, and its fields are checked again.
//
// RequestSigned is set once a signature is verified.
func (req *IdpAuthnRequest) verifySignature() error {
	switch {
	case req.simpleSign != nil:
		if err := req.verifySimpleSignSignature(); err != nil {
			return fmt.Errorf("cannot verify HTTP-POST-SimpleSign signature: %w", err)
		}
		req.RequestSigned = true
		return nil

	case req.redirectMessage != nil && req.redirectMessage.SignedContent != nil:
		if err := req.verifyRedirectSignature(); err != nil {
			return classify(fmt.Errorf("cannot verify HTTP-Redirect signature: %w", err), ErrInvalidSignature)
		}
		req.RequestSigned = true
		return nil

	case req.Request.Signature != nil:
		if err := req.verifyEnvelopedSignature(); err != nil {
			return classify(fmt.Errorf("cannot verify signature of authn request: %w", err), ErrInvalidSignature)
		}
		// Check what the signature covers, not what came with it.
		if err := req.validateFields(); err != nil {
			return err
		}
		req.RequestSigned = true
		return nil

	case req.IDP.WantAuthnRequestsSigned:
		return classify(fmt.Errorf("%w, and the IdP wants signed authn requests", errAuthnRequestNotSigned), ErrInvalidSignature)

	case spSignsAuthnRequests(req.ServiceProviderMetadata):
		return classify(fmt.Errorf("%w, but the metadata of %s says it signs them", errAuthnRequestNotSigned, req.ServiceProviderMetadata.EntityID), ErrInvalidSignature)
	}
	return nil
}

// verifyRedirectSignature checks the query string signature of a request
// received with the HTTP-Redirect binding.
func (req *IdpAuthnRequest) verifyRedirectSignature() error {
	if err := checkSigAlgNotSHA1(req.IDP.RejectSHA1Signatures, req.redirectMessage.SigAlg); err != nil {
		return err
	}
	certs, err := spSigningCerts(req.ServiceProviderMetadata)
	if err != nil {
		return err
	}
	// As for SimpleSign, the certificates' validity periods are not checked.
	return checkRedirectBindingSignature(req.redirectMessage, func() ([]*x509.Certificate, error) {
		return certs, nil
	}, req.Now, true)
}

// verifyEnvelopedSignature checks the enveloped XML signature of the
// request and reads Request again from what it covers.
func (req *IdpAuthnRequest) verifyEnvelopedSignature() error {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(req.RequestBuffer); err != nil {
		return classify(fmt.Errorf("cannot parse authn request: %w", err), ErrMalformedMessage)
	}
	root := doc.Root()
	if root == nil {
		return classify(errors.New("cannot parse authn request: no root element"), ErrMalformedMessage)
	}
	if err := checkEnvelopedSignatureNotSHA1(req.IDP.RejectSHA1Signatures, root); err != nil {
		return err
	}
	certs, err := spSigningCerts(req.ServiceProviderMetadata)
	if err != nil {
		return err
	}
	signed, err := verifiedEnvelopedElement(root, certs, req.IDP.dsigClock())
	if err != nil {
		return err
	}

	issuer := req.Request.Issuer.Value
	req.Request = AuthnRequest{}
	if err := unmarshalElement(signed, &req.Request); err != nil {
		return classify(fmt.Errorf("cannot parse authn request: %w", err), ErrMalformedMessage)
	}
	if req.Request.Issuer == nil || req.Request.Issuer.Value != issuer {
		return fmt.Errorf("signed authn request is not from %s", issuer)
	}
	return nil
}

// spSignsAuthnRequests reports whether a service provider's metadata says
// it signs its AuthnRequests: AuthnRequestsSigned="true" on one of its
// SPSSODescriptors.
func spSignsAuthnRequests(metadata *EntityDescriptor) bool {
	for _, d := range metadata.SPSSODescriptors {
		if d.AuthnRequestsSigned != nil && *d.AuthnRequestsSigned {
			return true
		}
	}
	return false
}
