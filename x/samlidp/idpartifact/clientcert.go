package idpartifact

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/beevik/etree"

	"github.com/crewjam/saml"
)

const xmldsigNamespace = "http://www.w3.org/2000/09/xmldsig#"

// peerCertificate returns the TLS client certificate of r: that of
// Binding.ClientCertificate, or else the first of r.TLS.PeerCertificates.
func (b *Binding) peerCertificate(r *http.Request) *x509.Certificate {
	if b.ClientCertificate != nil {
		return b.ClientCertificate(r)
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil
	}
	return r.TLS.PeerCertificates[0]
}

// tlsAuthenticated returns el, an unsigned ArtifactResolve, detached from
// its envelope, if the TLS client certificate of r has the public key of a
// signing certificate in md, the metadata of the SP that el names as its
// Issuer (saml-bindings §3.6.5.2). As for a signature
// (saml.IdentityProvider.ValidateSPSignedElement), the validity periods of
// the certificates in md are not checked.
func (b *Binding) tlsAuthenticated(r *http.Request, md *saml.EntityDescriptor, el *etree.Element) (*etree.Element, error) {
	peer := b.peerCertificate(r)
	if peer == nil {
		return nil, errors.New("idpartifact: the ArtifactResolve is not signed, and the request has no TLS client certificate")
	}
	for _, d := range md.SPSSODescriptors {
		for _, cert := range signingCerts(d.KeyDescriptors) {
			if bytes.Equal(cert.RawSubjectPublicKeyInfo, peer.RawSubjectPublicKeyInfo) {
				return detach(el), nil
			}
		}
	}
	return nil, fmt.Errorf("idpartifact: the ArtifactResolve is not signed, and the TLS client certificate is not a signing certificate of the SP %s", md.EntityID)
}

// signingCerts returns the certificates of keyDescriptors whose use is
// "signing" or unspecified (saml-metadata §2.4.1.1). One that cannot be
// parsed is skipped, since it can match no client certificate.
func signingCerts(keyDescriptors []saml.KeyDescriptor) []*x509.Certificate {
	var certs []*x509.Certificate
	for _, kd := range keyDescriptors {
		if kd.Use != "" && kd.Use != "signing" {
			continue
		}
		for _, c := range kd.KeyInfo.X509Data.X509Certificates {
			der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(c.Data), ""))
			if err != nil {
				continue
			}
			if cert, err := x509.ParseCertificate(der); err == nil {
				certs = append(certs, cert)
			}
		}
	}
	return certs
}

// isSigned reports whether el has an enveloped XML signature: a
// ds:Signature child.
func isSigned(el *etree.Element) bool {
	for _, c := range el.ChildElements() {
		if c.Tag == "Signature" && c.NamespaceURI() == xmldsigNamespace {
			return true
		}
	}
	return false
}

// detach returns a copy of el that declares the namespaces it inherits
// from its ancestors, so that it reads the same on its own.
func detach(el *etree.Element) *etree.Element {
	c := el.Copy()
	declared := map[string]bool{}
	isDecl := func(a etree.Attr) bool { return a.Space == "xmlns" || (a.Space == "" && a.Key == "xmlns") }
	for _, a := range c.Attr {
		if isDecl(a) {
			declared[a.FullKey()] = true
		}
	}
	for p := el.Parent(); p != nil; p = p.Parent() {
		for _, a := range p.Attr {
			if isDecl(a) && !declared[a.FullKey()] {
				declared[a.FullKey()] = true
				c.CreateAttr(a.FullKey(), a.Value)
			}
		}
	}
	return c
}
