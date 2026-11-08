package server

import (
	"crypto"
	"encoding/xml"
	"fmt"
	"strings"
	"time"

	"github.com/beevik/etree"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/tools/gosamldev/inspect"
	"github.com/crewjam/saml/xmlenc"
)

// fact is one row of the Result page's Assertion list.
type fact struct {
	K, V string
	// Mono marks a technical value; Time a time, shown in the viewer's
	// zone with At as its datetime.
	Mono bool
	At   time.Time
}

// validityView is the Result page's validity window: a bar from
// NotBefore to NotOnOrAfter with a mark at the time that matters, the
// login (Accepted) or the arrival (Refused, when it came too late).
type validityView struct {
	Len                     string
	NotBefore, NotOnOrAfter time.Time
	// Mid labels the mark; MarkAt is the time it stands for.
	Mid    string
	MarkAt time.Time
	// Mark is the mark's position as a class, at-0 … at-100 in steps of
	// 5 (inline styles are not allowed by the CSP). Late puts the mark
	// past the end of the bar instead.
	Mark string
	Late bool
}

// unverifiedAssertion reads the first unencrypted Assertion in a
// Response that was refused, to show what it said. Nothing here is
// trusted: the page says so.
func unverifiedAssertion(responseXML string) *saml.Assertion {
	if responseXML == "" {
		return nil
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromString(responseXML); err != nil {
		return nil
	}
	el := doc.FindElement("//Assertion")
	if el == nil {
		return nil
	}
	d := etree.NewDocument()
	d.SetRoot(el.Copy())
	b, err := d.WriteToBytes()
	if err != nil {
		return nil
	}
	var a saml.Assertion
	if err := xml.Unmarshal(b, &a); err != nil {
		return nil
	}
	return &a
}

// decryptedForDisplay decrypts the EncryptedAssertion of a refused
// Response with the SP's key, to show what it said. It is shown only to
// the browser that created the SP, which can read everything the SP
// holds anyway; to anyone else it would be a decryption oracle.
func decryptedForDisplay(key crypto.PrivateKey, responseXML string) *saml.Assertion {
	doc := etree.NewDocument()
	if err := doc.ReadFromString(responseXML); err != nil {
		return nil
	}
	ea := doc.FindElement("//EncryptedAssertion")
	if ea == nil {
		return nil
	}
	data := ea.FindElement("./EncryptedData")
	if data == nil {
		return nil
	}
	var plain []byte
	var err error
	if ek := ea.FindElement("./EncryptedKey"); ek != nil {
		// The content key beside the EncryptedData, as Entra ID sends it.
		var cek []byte
		if cek, err = xmlenc.Decrypt(key, ek); err == nil {
			plain, err = xmlenc.Decrypt(cek, data)
		}
	} else {
		plain, err = xmlenc.Decrypt(key, data)
	}
	if err != nil {
		return nil
	}
	return unverifiedAssertion(string(plain))
}

// assertionFacts lists what an assertion says, for the Result page.
// inResponseTo is what the SP matched, or "" for an unsolicited login;
// for an untrusted assertion, pass what its SubjectConfirmationData says.
func assertionFacts(a *saml.Assertion, inResponseTo string, unsolicitedOK bool) []fact {
	var out []fact
	if a.Subject != nil && a.Subject.NameID != nil {
		out = append(out, fact{K: "NameID", V: a.Subject.NameID.Value, Mono: true})
		if a.Subject.NameID.Format != "" {
			out = append(out, fact{K: "NameID format", V: a.Subject.NameID.Format, Mono: true})
		}
	}
	if a.Issuer.Value != "" {
		out = append(out, fact{K: "Issuer", V: a.Issuer.Value, Mono: true})
	}
	switch {
	case inResponseTo != "":
		out = append(out, fact{K: "In response to", V: inResponseTo, Mono: true})
	case unsolicitedOK:
		out = append(out, fact{K: "In response to", V: "nothing: an IdP-initiated login"})
	}
	for i, s := range a.AuthnStatements {
		if i == 0 {
			if !s.AuthnInstant.IsZero() {
				out = append(out, fact{K: "Authenticated", At: s.AuthnInstant})
			}
			if s.AuthnContext.AuthnContextClassRef != nil {
				out = append(out, fact{K: "Authn context", V: s.AuthnContext.AuthnContextClassRef.Value, Mono: true})
			}
		}
		if s.SessionIndex != "" {
			out = append(out, fact{K: "Session index", V: s.SessionIndex, Mono: true})
		}
		if s.SessionNotOnOrAfter != nil {
			out = append(out, fact{K: "Session ends", At: *s.SessionNotOnOrAfter})
		}
	}
	if a.ID != "" {
		out = append(out, fact{K: "Assertion ID", V: a.ID, Mono: true})
	}
	if a.Conditions != nil && !a.Conditions.NotOnOrAfter.IsZero() {
		out = append(out, fact{K: "Valid until", At: a.Conditions.NotOnOrAfter})
	}
	return out
}

// subjectInResponseTo is the InResponseTo of an assertion's first
// bearer confirmation, for an assertion the SP did not accept.
func subjectInResponseTo(a *saml.Assertion) string {
	if a.Subject == nil {
		return ""
	}
	for _, sc := range a.Subject.SubjectConfirmations {
		if sc.SubjectConfirmationData != nil && sc.SubjectConfirmationData.InResponseTo != "" {
			return sc.SubjectConfirmationData.InResponseTo
		}
	}
	return ""
}

// validity builds the validity window of an assertion: for an accepted
// login the mark is when the user authenticated; for a refused one it is
// when the Response arrived.
func validity(a *saml.Assertion, arrived time.Time, accepted bool) *validityView {
	if a.Conditions == nil || a.Conditions.NotBefore.IsZero() || a.Conditions.NotOnOrAfter.IsZero() {
		return nil
	}
	nb, na := a.Conditions.NotBefore, a.Conditions.NotOnOrAfter
	if !na.After(nb) {
		return nil
	}
	v := &validityView{NotBefore: nb, NotOnOrAfter: na, Len: spanText(na.Sub(nb))}
	v.MarkAt = arrived
	v.Mid = "arrived"
	if accepted && len(a.AuthnStatements) > 0 && !a.AuthnStatements[0].AuthnInstant.IsZero() {
		v.MarkAt = a.AuthnStatements[0].AuthnInstant
		v.Mid = "authenticated"
	}
	if !accepted && !arrived.Before(na) {
		v.Late = true
		v.Len += ", expired"
		v.Mid = "arrived " + spanText(arrived.Sub(na)) + " after expiry"
		return v
	}
	pos := float64(v.MarkAt.Sub(nb)) / float64(na.Sub(nb))
	pos = min(max(pos, 0), 1)
	v.Mark = fmt.Sprintf("at-%d", int(pos*20+0.5)*5)
	return v
}

// spanText says how long a duration is, roughly, in words.
func spanText(d time.Duration) string {
	plural := func(n int, unit string) string {
		if n == 1 {
			return "1 " + unit
		}
		return fmt.Sprintf("%d %ss", n, unit)
	}
	switch {
	case d < 2*time.Minute:
		return plural(int(d.Round(time.Second)/time.Second), "second")
	case d < 2*time.Hour:
		return plural(int(d.Round(time.Minute)/time.Minute), "minute")
	case d < 48*time.Hour:
		return plural(int(d.Round(time.Hour)/time.Hour), "hour")
	}
	return plural(int(d.Round(24*time.Hour)/(24*time.Hour)), "day")
}

// relaxedBy says which of the SP's relaxed checks a Response needed to
// be accepted, if any: it reads the signatures and encryption of the
// Response as received and of the (decrypted) assertion.
func relaxedBy(cfg *SPConfig, responseXML, assertionXML string, at time.Time) (reasons []string, signature string) {
	if !cfg.AllowSHA1 && !cfg.AllowUnsignedCBC {
		return nil, ""
	}
	var sigs []inspect.Signature
	responseSigned, cbc := false, false
	for _, x := range []string{responseXML, assertionXML} {
		if x == "" {
			continue
		}
		for _, m := range inspect.Parse(x, at).Messages {
			for _, s := range m.Signatures {
				sigs = append(sigs, s)
				if strings.HasPrefix(s.Signs, "Response") {
					responseSigned = true
				}
			}
			for _, w := range m.Warnings {
				if strings.Contains(w, "AES-CBC") {
					cbc = true
				}
			}
		}
	}
	if cfg.AllowSHA1 {
		for _, s := range sigs {
			sm, dm := algorithmURI(s.SignatureMethod), algorithmURI(s.DigestMethod)
			if strings.HasSuffix(sm, "sha1") || strings.HasSuffix(dm, "#sha1") {
				what, _, _ := strings.Cut(s.Signs, " ")
				alg := sm[strings.LastIndex(sm, "#")+1:]
				reasons = append(reasons, "the "+strings.ToLower(what)+" is signed with "+alg)
				signature = alg + " · accepted by Relax checks"
				break
			}
		}
	}
	if cfg.AllowUnsignedCBC && cbc && !responseSigned {
		reasons = append(reasons, "the assertion is encrypted with AES-CBC in a Response that is not signed")
		if signature == "" {
			signature = "Response not signed; AES-CBC accepted by Relax checks"
		}
	}
	return reasons, signature
}

// algorithmURI is the URI in an algorithm as the inspect package names
// it, "RSA-SHA-1 (http://…#rsa-sha1)", or the whole string.
func algorithmURI(s string) string {
	if i := strings.LastIndex(s, "("); i >= 0 && strings.HasSuffix(s, ")") {
		return s[i+1 : len(s)-1]
	}
	return s
}
