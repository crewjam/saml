package artifact

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

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
// signing certificate of the IdP of sp (saml-bindings §3.6.5.2). As for a
// signature, a certificate outside its validity period does not count,
// unless sp.IgnoreCertificateExpiry is set, nor does expired IdP metadata
// when sp.RejectExpiredIDPMetadata is set.
func (b *Binding) tlsAuthenticated(r *http.Request, sp *saml.ServiceProvider, el *etree.Element) (*etree.Element, error) {
	peer := b.peerCertificate(r)
	if peer == nil {
		return nil, errors.New("artifact: the ArtifactResolve is not signed, and the request has no TLS client certificate")
	}
	md, t := sp.IDPMetadata, now(sp)
	if md == nil {
		return nil, errors.New("artifact: IDPMetadata is not set")
	}
	if sp.RejectExpiredIDPMetadata {
		if err := checkNotExpired(md, t); err != nil {
			return nil, err
		}
	}
	for _, d := range md.IDPSSODescriptors {
		for _, cert := range signingCerts(d.KeyDescriptors) {
			if !bytes.Equal(cert.RawSubjectPublicKeyInfo, peer.RawSubjectPublicKeyInfo) {
				continue
			}
			if !sp.IgnoreCertificateExpiry && (t.Before(cert.NotBefore) || t.After(cert.NotAfter)) {
				continue
			}
			return detach(el), nil
		}
	}
	return nil, fmt.Errorf("artifact: the ArtifactResolve is not signed, and the TLS client certificate is not a signing certificate of the IdP %s", md.EntityID)
}

// checkNotExpired returns an error matching saml.ErrExpired if md, or one
// of its IDPSSODescriptors, has a validUntil that has passed at t.
func checkNotExpired(md *saml.EntityDescriptor, t time.Time) error {
	validUntil := md.ValidUntil
	for _, d := range md.IDPSSODescriptors {
		if v := d.ValidUntil; v != nil && !v.IsZero() && (validUntil.IsZero() || v.Before(validUntil)) {
			validUntil = *v
		}
	}
	if !validUntil.IsZero() && !t.Before(validUntil) {
		return fmt.Errorf("artifact: the metadata of the IdP %s expired at %s: %w", md.EntityID, validUntil.UTC().Format(time.RFC3339), saml.ErrExpired)
	}
	return nil
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
