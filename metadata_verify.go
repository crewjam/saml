package saml

import (
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/beevik/etree"
	"github.com/russellhaering/goxmldsig/etreeutils"

	"github.com/crewjam/saml/internal/xmlroundtrip"
)

// metadataNamespace is the namespace of SAML metadata elements.
const metadataNamespace = "urn:oasis:names:tc:SAML:2.0:metadata"

// VerifyMetadataSignature checks that the root element of the SAML metadata
// in data, an EntityDescriptor or an EntitiesDescriptor, carries a valid
// enveloped XML signature made with one of certs (saml-metadata-2.0-os §3).
// It returns the metadata the signature covers: the root element without its
// Signature, in the canonical form that was digested.
//
// Parse the returned bytes, not data. Anything data holds that the signature
// does not cover, such as namespace declarations that exclusive
// canonicalization leaves out, is not in them.
//
// Only a signature on the root element counts: in an aggregate, signatures
// on the EntityDescriptors inside are not checked. The certificates'
// validity periods are not checked, as for other certificates taken from
// metadata, and neither are the metadata's validUntil and cacheDuration.
func VerifyMetadataSignature(data []byte, certs []*x509.Certificate) ([]byte, error) {
	return verifyMetadataSignature(data, certs, false)
}

// VerifyMetadataSignatureRejectSHA1 is VerifyMetadataSignature, except that
// it also refuses a signature whose SignatureMethod or DigestMethod is
// based on SHA-1, with an error that matches ErrUnsupported.
func VerifyMetadataSignatureRejectSHA1(data []byte, certs []*x509.Certificate) ([]byte, error) {
	return verifyMetadataSignature(data, certs, true)
}

func verifyMetadataSignature(data []byte, certs []*x509.Certificate, rejectSHA1 bool) ([]byte, error) {
	if len(certs) == 0 {
		return nil, errors.New("cannot verify metadata signature: no certificate to verify it with")
	}

	if err := xmlroundtrip.Validate(data); err != nil {
		return nil, classify(fmt.Errorf("invalid xml: %w", err), ErrMalformedMessage)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(data); err != nil {
		return nil, classify(fmt.Errorf("invalid xml: %w", err), ErrMalformedMessage)
	}
	root := doc.Root()
	if root == nil {
		return nil, classify(errors.New("invalid xml: no root"), ErrMalformedMessage)
	}

	ctx, err := etreeutils.NSBuildParentContext(root)
	if err != nil {
		return nil, classify(err, ErrMalformedMessage)
	}
	ctx, err = ctx.SubContext(root)
	if err != nil {
		return nil, classify(err, ErrMalformedMessage)
	}
	ns, err := ctx.LookupPrefix(root.Space)
	if err != nil || ns != metadataNamespace || (root.Tag != "EntityDescriptor" && root.Tag != "EntitiesDescriptor") {
		return nil, classify(fmt.Errorf("expected an EntityDescriptor or EntitiesDescriptor in %s, not %s", metadataNamespace, root.Tag), ErrMalformedMessage)
	}

	if err := checkEnvelopedSignatureNotSHA1(rejectSHA1, root); err != nil {
		return nil, classify(fmt.Errorf("cannot validate signature on %s: %w", root.Tag, err), ErrInvalidSignature)
	}
	signed, err := verifiedEnvelopedElement(root, certs, nil)
	if err != nil {
		if errors.Is(err, errSignatureElementNotPresent) {
			return nil, classify(errors.New("metadata is not signed"), ErrInvalidSignature)
		}
		return nil, classify(fmt.Errorf("cannot validate signature on %s: %w", root.Tag, err), ErrInvalidSignature)
	}

	out := etree.NewDocument()
	out.SetRoot(signed)
	return out.WriteToBytes()
}
