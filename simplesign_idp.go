package saml

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"

	"github.com/beevik/etree"
)

// verifySimpleSignSignature checks the HTTP-POST-SimpleSign signature of the
// authentication request against the signing certificates in the service
// provider's metadata. The signed content is built from RequestBuffer and
// RelayState, so the signature covers exactly the request that Validate
// parsed and the relay state that is sent back.
func (req *IdpAuthnRequest) verifySimpleSignSignature() error {
	m := *req.simpleSign
	m.XML = req.RequestBuffer
	m.RelayState = req.RelayState
	m.HasRelayState = m.HasRelayState || req.RelayState != ""

	algorithm, signature, err := decodeDetachedSignature(m.SigAlg, m.Signature, simpleSignBase64)
	if err != nil {
		return err
	}
	certs, err := spSigningCerts(req.ServiceProviderMetadata)
	if err != nil {
		return fmt.Errorf("cannot validate signature: %w", err)
	}
	// The validity period of the certificates is not checked: the SP
	// metadata is the trust anchor and its certificates are only containers
	// for the key (SAML V2.0 Metadata Interoperability Profile), and the IdP
	// has no setting to opt out of such a check.
	return checkDetachedSignature(algorithm, m.signedContent(), signature, certs, req.Now, true)
}

// spSigningCerts returns the signing certificates in the SPSSODescriptors of
// a service provider's metadata: those of key descriptors whose use is
// "signing" or unspecified.
func spSigningCerts(metadata *EntityDescriptor) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for _, spssoDescriptor := range metadata.SPSSODescriptors {
		for _, keyDescriptor := range spssoDescriptor.KeyDescriptors {
			if keyDescriptor.Use != "" && keyDescriptor.Use != "signing" {
				continue
			}
			for _, certificate := range keyDescriptor.KeyInfo.X509Data.X509Certificates {
				if certificate.Data == "" {
					continue
				}
				cert, err := parseCert(certificate.Data)
				if err != nil {
					return nil, err
				}
				certs = append(certs, cert)
			}
		}
	}
	if len(certs) == 0 {
		return nil, errors.New("cannot find any signing certificate in the SP SSO descriptor")
	}
	return certs, nil
}

// IdpAuthnRequestSimpleSignForm contains the HTML form information to be
// submitted to an ACS endpoint with the HTTP-POST-SimpleSign binding.
type IdpAuthnRequestSimpleSignForm struct {
	URL          string
	SAMLResponse string
	RelayState   string

	// SigAlg and Signature are the SimpleSign signature algorithm and the
	// base64 encoded signature over the response XML, RelayState (when not
	// empty) and SigAlg.
	SigAlg    string
	Signature string
}

// SimpleSignBinding creates the HTTP-POST-SimpleSign form information for
// this IdpAuthnRequest, which must have an ACS endpoint with that binding.
// If ResponseEl is not already set, it calls MakeResponse to produce it.
//
// The Response and its Assertion keep the enveloped XML signatures
// MakeResponse gives them (sstc-saml-binding-simplesign-cs-01 §2.4 says such
// signatures MUST remain intact), so a service provider that ignores the
// SimpleSign signature can still check them. The SimpleSign signature is
// made with the IdP's key and SignatureMethod (by default SHA-256 for the key
// type). The relay state is signed, and sent, only when it is not empty.
func (req *IdpAuthnRequest) SimpleSignBinding() (IdpAuthnRequestSimpleSignForm, error) {
	var form IdpAuthnRequestSimpleSignForm

	if req.ACSEndpoint == nil || req.ACSEndpoint.Binding != HTTPPostSimpleSignBinding {
		binding := ""
		if req.ACSEndpoint != nil {
			binding = req.ACSEndpoint.Binding
		}
		return form, fmt.Errorf("ACS endpoint binding is %q, not HTTP-POST-SimpleSign", binding)
	}

	if req.ResponseEl == nil {
		if err := req.MakeResponse(); err != nil {
			return form, err
		}
	}

	doc := etree.NewDocument()
	doc.SetRoot(req.ResponseEl)
	responseBuf, err := doc.WriteToBytes()
	if err != nil {
		return form, err
	}

	signingContext, err := req.signingContext()
	if err != nil {
		return form, err
	}
	sigAlg, signature, err := signSimpleSign(signingContext, redirectParamSAMLResponse, responseBuf, req.RelayState)
	if err != nil {
		return form, err
	}

	form.URL = req.ACSEndpoint.Location
	form.SAMLResponse = base64.StdEncoding.EncodeToString(responseBuf)
	form.RelayState = req.RelayState
	form.SigAlg = sigAlg
	form.Signature = signature
	return form, nil
}

// defaultSimpleSignResponseFormTemplate is defaultResponseFormTemplate with
// the SimpleSign signature fields. RelayState is only included when it is
// not empty, because a RelayState field, even an empty one, is signed.
var defaultSimpleSignResponseFormTemplate = template.Must(template.New("saml-simplesign-form").Parse(`<html>` +
	`<form method="post" action="{{.URL}}" id="SAMLResponseForm">` +
	`<input type="hidden" name="SAMLResponse" value="{{.SAMLResponse}}" />` +
	`{{if .RelayState}}<input type="hidden" name="RelayState" value="{{.RelayState}}" />{{end}}` +
	`<input type="hidden" name="SigAlg" value="{{.SigAlg}}" />` +
	`<input type="hidden" name="Signature" value="{{.Signature}}" />` +
	`<input id="SAMLSubmitButton" type="submit" value="Continue" />` +
	`</form>` +
	`<script>document.getElementById('SAMLSubmitButton').style.visibility='hidden';</script>` +
	`<script>document.getElementById('SAMLResponseForm').submit();</script>` +
	`</html>`))

// writeSimpleSignResponse writes the auto-submitting HTML form that sends
// the response with the HTTP-POST-SimpleSign binding.
func (req *IdpAuthnRequest) writeSimpleSignResponse(w http.ResponseWriter) error {
	form, err := req.SimpleSignBinding()
	if err != nil {
		return err
	}

	tmpl := req.IDP.SimpleSignResponseFormTemplate
	if tmpl == nil {
		tmpl = defaultSimpleSignResponseFormTemplate
	}

	buf := bytes.NewBuffer(nil)
	if err := tmpl.Execute(buf, form); err != nil {
		return err
	}
	_, err = io.Copy(w, buf)
	return err
}
