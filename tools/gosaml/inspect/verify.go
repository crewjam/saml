package inspect

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// Check is the outcome of checking a signature with some certificates.
type Check struct {
	OK bool `json:"ok"`
	// By describes the certificate that verified the signature.
	By    string `json:"by,omitempty"`
	Error string `json:"error,omitempty"`
}

// DetachedSignature is a signature carried by binding parameters rather
// than in the XML: the SigAlg and Signature of the HTTP-Redirect and
// HTTP-POST-SimpleSign bindings.
type DetachedSignature struct {
	Binding string `json:"binding"`
	SigAlg  string `json:"sigAlg"`
	// Trust is the check against the certificates given to
	// ParseWithKeys; nil if none were.
	Trust *Check `json:"trust,omitempty"`
}

// detached is what checking a detached signature needs.
type detached struct {
	sigAlg        string
	signature     string
	signedContent []byte
}

var detachedAlgorithms = map[string]x509.SignatureAlgorithm{
	dsig.RSASHA1SignatureMethod:     x509.SHA1WithRSA,
	dsig.RSASHA256SignatureMethod:   x509.SHA256WithRSA,
	dsig.RSASHA384SignatureMethod:   x509.SHA384WithRSA,
	dsig.RSASHA512SignatureMethod:   x509.SHA512WithRSA,
	dsig.ECDSASHA1SignatureMethod:   x509.ECDSAWithSHA1,
	dsig.ECDSASHA256SignatureMethod: x509.ECDSAWithSHA256,
	dsig.ECDSASHA384SignatureMethod: x509.ECDSAWithSHA384,
	dsig.ECDSASHA512SignatureMethod: x509.ECDSAWithSHA512,
}

// ParseWithKeys is Parse, and also checks every signature against the
// certificates in keys: PEM certificates, base64 DER, or metadata, whose
// certificates are all used. Each XML signature is also checked with the
// certificate in its own KeyInfo, if it has one, which shows whether the
// message is intact but not who signed it.
func ParseWithKeys(input, keys string, now time.Time) *Result {
	res := Parse(input, now)
	var certs []*x509.Certificate
	if strings.TrimSpace(keys) != "" {
		var err error
		certs, err = ParseCertificates(keys)
		if err != nil {
			res.KeysError = err.Error()
		}
		for _, c := range certs {
			d := describeCertificate(base64.StdEncoding.EncodeToString(c.Raw), now)
			d.Where = "given to check signatures with"
			res.Keys = append(res.Keys, d)
		}
	}
	verify(res, certs, strings.TrimSpace(keys) != "")
	return res
}

// ParseCertificates reads certificates from PEM, base64 DER, or SAML
// metadata (every X509Certificate in it).
func ParseCertificates(text string) ([]*x509.Certificate, error) {
	text = strings.TrimSpace(strings.TrimPrefix(text, "\ufeff"))
	var certs []*x509.Certificate
	switch {
	case strings.Contains(text, "-----BEGIN"):
		rest := []byte(text)
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return certs, fmt.Errorf("a PEM block is not a valid certificate: %w", err)
			}
			certs = append(certs, c)
		}
	case strings.HasPrefix(text, "<"):
		doc := etree.NewDocument()
		if err := doc.ReadFromString(text); err != nil {
			return nil, fmt.Errorf("not well-formed XML: %w", err)
		}
		for _, el := range doc.FindElements("//X509Certificate") {
			c, err := parseBase64Certificate(el.Text())
			if err != nil {
				return certs, err
			}
			certs = append(certs, c)
		}
	default:
		c, err := parseBase64Certificate(text)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, errors.New("no certificate found: paste PEM, base64 DER, or metadata")
	}
	return certs, nil
}

func parseBase64Certificate(text string) (*x509.Certificate, error) {
	der, err := decodeBase64(text)
	if err != nil {
		return nil, fmt.Errorf("a certificate is not valid base64: %w", err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("not a valid certificate: %w", err)
	}
	return c, nil
}

func certLabel(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return c.Subject.String() + " (SHA-256 " + colonHex(sum[:])[:23] + "…)"
}

// verify checks the signatures Parse found.
func verify(res *Result, certs []*x509.Certificate, haveKeys bool) {
	if d := res.detached; d != nil {
		ds := &DetachedSignature{Binding: res.Binding, SigAlg: d.sigAlg}
		if haveKeys {
			ds.Trust = checkDetached(d, certs)
		}
		res.Detached = ds
	}
	for _, m := range res.Messages {
		if m.raw == nil || len(m.Signatures) == 0 {
			continue
		}
		doc := etree.NewDocument()
		if err := doc.ReadFromBytes(m.raw); err != nil {
			continue
		}
		pairs := signedElements(messageRoot(doc.Root()))
		for i := range m.Signatures {
			if i >= len(pairs) {
				break
			}
			parent, sig := pairs[i][0], pairs[i][1]
			if embedded := keyInfoCertificates(sig); len(embedded) > 0 {
				m.Signatures[i].Integrity = checkXML(parent, embedded)
			}
			if haveKeys {
				m.Signatures[i].Trust = checkXML(parent, certs)
			}
		}
	}
}

// checkXML checks the enveloped signature of el with each of certs.
func checkXML(el *etree.Element, certs []*x509.Certificate) *Check {
	if len(certs) == 0 {
		return &Check{Error: "no certificate to check with"}
	}
	var lastErr error
	for _, cert := range certs {
		ctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}})
		ctx.IdAttribute = "ID"
		// Check the signature itself, whatever the time: whether the
		// certificate has expired is reported separately.
		ctx.Clock = dsig.NewFakeClockAt(cert.NotBefore.Add(cert.NotAfter.Sub(cert.NotBefore) / 2))
		if _, err := ctx.Validate(detach(el)); err != nil {
			lastErr = err
			continue
		}
		return &Check{OK: true, By: certLabel(cert)}
	}
	msg := lastErr.Error()
	if strings.Contains(msg, "Could not verify certificate against trusted certs") {
		msg = "the signature's KeyInfo carries a different certificate from the one(s) given: " + msg
	}
	return &Check{Error: msg}
}

// checkDetached checks a binding signature with each of certs.
func checkDetached(d *detached, certs []*x509.Certificate) *Check {
	alg, ok := detachedAlgorithms[d.sigAlg]
	if !ok {
		return &Check{Error: fmt.Sprintf("unsupported SigAlg %q", d.sigAlg)}
	}
	sig, err := base64.StdEncoding.DecodeString(d.signature)
	if err != nil {
		return &Check{Error: "the Signature parameter is not valid base64: " + err.Error()}
	}
	if len(certs) == 0 {
		return &Check{Error: "no certificate to check with"}
	}
	var lastErr error
	for _, cert := range certs {
		if err := cert.CheckSignature(alg, d.signedContent, sig); err != nil {
			lastErr = err
			continue
		}
		return &Check{OK: true, By: certLabel(cert)}
	}
	return &Check{Error: lastErr.Error()}
}

func keyInfoCertificates(sig *etree.Element) []*x509.Certificate {
	var out []*x509.Certificate
	for _, el := range sig.FindElements("./KeyInfo//X509Certificate") {
		if c, err := parseBase64Certificate(el.Text()); err == nil {
			out = append(out, c)
		}
	}
	return out
}

// messageRoot returns the SAML message in a document: the root, or the
// content of a SOAP Body.
func messageRoot(root *etree.Element) *etree.Element {
	if root != nil && root.Tag == "Envelope" && root.NamespaceURI() == nsSOAP11 {
		if body := child(root, nsSOAP11, "Body"); body != nil && len(body.ChildElements()) > 0 {
			return body.ChildElements()[0]
		}
	}
	return root
}

// signedElements returns each ds:Signature under root with the element it
// is in, in document order.
func signedElements(root *etree.Element) [][2]*etree.Element {
	var out [][2]*etree.Element
	var walk func(el *etree.Element)
	walk = func(el *etree.Element) {
		for _, c := range el.ChildElements() {
			if c.Tag == "Signature" && c.NamespaceURI() == nsDSig {
				out = append(out, [2]*etree.Element{el, c})
				continue
			}
			walk(c)
		}
	}
	if root != nil {
		walk(root)
	}
	return out
}

// detachedFromQuery returns the signed content of an HTTP-Redirect
// signature, from the raw (still URL-encoded) query, as
// saml-bindings §3.4.4.1 defines it.
func detachedFromQuery(rawQuery string) *detached {
	raw := map[string]string{}
	for _, pair := range strings.Split(rawQuery, "&") {
		k, v, _ := strings.Cut(pair, "=")
		if _, seen := raw[k]; !seen {
			raw[k] = v
		}
	}
	sigAlg, hasAlg := raw["SigAlg"]
	signature, hasSig := raw["Signature"]
	if !hasAlg || !hasSig {
		return nil
	}
	param := "SAMLRequest"
	if _, ok := raw["SAMLResponse"]; ok {
		param = "SAMLResponse"
	}
	content := param + "=" + raw[param]
	if rs, ok := raw["RelayState"]; ok {
		content += "&RelayState=" + rs
	}
	content += "&SigAlg=" + sigAlg
	d := &detached{signedContent: []byte(content)}
	d.sigAlg, _ = urlUnescape(sigAlg)
	d.signature, _ = urlUnescape(signature)
	return d
}

// detachedFromForm returns the signed content of an HTTP-POST-SimpleSign
// signature (sstc-saml-binding-simplesign-cs-01 §2.5): the decoded message
// and parameters, not URL-encoded.
func detachedFromForm(param string, message []byte, relayState string, hasRelayState bool, sigAlg, signature string) *detached {
	content := param + "=" + string(message)
	if hasRelayState {
		content += "&RelayState=" + relayState
	}
	content += "&SigAlg=" + sigAlg
	return &detached{sigAlg: sigAlg, signature: signature, signedContent: []byte(content)}
}
