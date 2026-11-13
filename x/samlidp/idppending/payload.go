package idppending

import (
	"strings"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlidp"
)

// payload is what a cookie holds: a samlidp.AuthnRequest, kept small with
// short names, empty fields left out and common URI prefixes abbreviated
// (see squeeze), and the handle's random value and the expiry.
//
// Every field of the AuthnRequest is kept, since each bears on the
// Response: those that Response reads to make it, those it copies into
// the saml.AuthnRequest that IdentityProviderOptions and assertion makers
// see (ProviderName, Consent, AttributeConsumingServiceIndex, Scoping,
// Extensions), and Signed, which ErrorResponse reads.
type payload struct {
	Token   string `json:"k"`
	Expires int64  `json:"z"`

	ID                             string   `json:"i,omitempty"`
	ServiceProvider                string   `json:"s"`
	IssueInstant                   int64    `json:"t,omitempty"` // Unix nanoseconds, 0 for the zero time
	RelayState                     string   `json:"r,omitempty"`
	ACSURL                         string   `json:"a,omitempty"`
	ACSBinding                     string   `json:"b,omitempty"`
	ProviderName                   string   `json:"pn,omitempty"`
	Consent                        string   `json:"co,omitempty"`
	AttributeConsumingServiceIndex string   `json:"ac,omitempty"`
	Scoping                        *scoping `json:"sc,omitempty"`
	ForceAuthn                     bool     `json:"f,omitempty"`
	IsPassive                      bool     `json:"p,omitempty"`
	NameIDFormat                   string   `json:"nf,omitempty"`
	SPNameQualifier                string   `json:"nq,omitempty"`
	AllowCreate                    bool     `json:"nc,omitempty"`
	AuthnContextComparison         string   `json:"cc,omitempty"`
	AuthnContextClasses            []string `json:"cl,omitempty"`
	AuthnContextDecls              []string `json:"cd,omitempty"`
	Subject                        *nameID  `json:"u,omitempty"`
	Signed                         bool     `json:"g,omitempty"`
	Extensions                     []string `json:"x,omitempty"`
}

type scoping struct {
	ProxyCount   *int       `json:"c,omitempty"`
	IDPEntries   []idpEntry `json:"e,omitempty"`
	HasIDPList   bool       `json:"l,omitempty"`
	GetComplete  string     `json:"g,omitempty"`
	RequesterIDs []string   `json:"r,omitempty"`
}

type idpEntry struct {
	ProviderID string `json:"p"`
	Name       string `json:"n,omitempty"`
	Loc        string `json:"l,omitempty"`
}

type nameID struct {
	NameQualifier   string `json:"q,omitempty"`
	SPNameQualifier string `json:"s,omitempty"`
	Format          string `json:"f,omitempty"`
	SPProvidedID    string `json:"p,omitempty"`
	Value           string `json:"v"`
}

// prefixes are the URI prefixes that squeeze abbreviates as "~" and a
// digit, its index. The list may grow, but never change: a cookie made
// before must still be read the same.
var prefixes = [...]string{
	"urn:oasis:names:tc:SAML:2.0:nameid-format:",
	"urn:oasis:names:tc:SAML:1.1:nameid-format:",
	"urn:oasis:names:tc:SAML:2.0:ac:classes:",
	"urn:oasis:names:tc:SAML:2.0:bindings:",
	"urn:oasis:names:tc:SAML:2.0:consent:",
	"https://",
}

// squeeze abbreviates the prefix of s that is one of prefixes as "~" and
// its index, and a leading "~" as "~~", so that expand can restore s.
func squeeze(s string) string {
	if strings.HasPrefix(s, "~") {
		return "~" + s
	}
	for i, prefix := range prefixes {
		if rest, ok := strings.CutPrefix(s, prefix); ok {
			return "~" + string(rune('0'+i)) + rest
		}
	}
	return s
}

// unsqueeze reverses squeeze, and returns false if s is malformed.
func unsqueeze(s string) (string, bool) {
	rest, ok := strings.CutPrefix(s, "~")
	switch {
	case !ok:
		return s, true
	case strings.HasPrefix(rest, "~"):
		return rest, true
	case rest != "" && rest[0] >= '0' && int(rest[0]-'0') < len(prefixes):
		return prefixes[rest[0]-'0'] + rest[1:], true
	default:
		return "", false
	}
}

func squeezeAll(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	out := make([]string, len(s))
	for i := range s {
		out[i] = squeeze(s[i])
	}
	return out
}

func unsqueezeAll(s []string) ([]string, bool) {
	if len(s) == 0 {
		return nil, true
	}
	out := make([]string, len(s))
	for i := range s {
		var ok bool
		if out[i], ok = unsqueeze(s[i]); !ok {
			return nil, false
		}
	}
	return out, true
}

// compact returns the payload that keeps req, without Token and Expires.
func compact(req *samlidp.AuthnRequest) payload {
	p := payload{
		ID:                             req.ID,
		ServiceProvider:                req.ServiceProvider,
		RelayState:                     req.RelayState,
		ACSURL:                         squeeze(req.ACSURL),
		ACSBinding:                     squeeze(req.ACSBinding),
		ProviderName:                   req.ProviderName,
		Consent:                        squeeze(req.Consent),
		AttributeConsumingServiceIndex: req.AttributeConsumingServiceIndex,
		ForceAuthn:                     req.ForceAuthn,
		IsPassive:                      req.IsPassive,
		NameIDFormat:                   squeeze(string(req.NameIDFormat)),
		SPNameQualifier:                req.SPNameQualifier,
		AllowCreate:                    req.AllowCreate,
		AuthnContextComparison:         string(req.AuthnContextComparison),
		AuthnContextDecls:              append([]string(nil), req.AuthnContextDecls...),
		Signed:                         req.Signed,
	}
	if !req.IssueInstant.IsZero() {
		p.IssueInstant = req.IssueInstant.UnixNano()
	}
	if len(req.AuthnContextClasses) > 0 {
		classes := make([]string, len(req.AuthnContextClasses))
		for i, c := range req.AuthnContextClasses {
			classes[i] = string(c)
		}
		p.AuthnContextClasses = squeezeAll(classes)
	}
	if s := req.Scoping; s != nil {
		p.Scoping = &scoping{ProxyCount: s.ProxyCount, RequesterIDs: append([]string(nil), s.RequesterIDs...)}
		if s.IDPList != nil {
			p.Scoping.HasIDPList = true
			p.Scoping.GetComplete = s.IDPList.GetComplete
			for _, e := range s.IDPList.IDPEntries {
				p.Scoping.IDPEntries = append(p.Scoping.IDPEntries, idpEntry{ProviderID: e.ProviderID, Name: e.Name, Loc: e.Loc})
			}
		}
	}
	if n := req.Subject; n != nil {
		p.Subject = &nameID{NameQualifier: n.NameQualifier, SPNameQualifier: n.SPNameQualifier,
			Format: squeeze(n.Format), SPProvidedID: n.SPProvidedID, Value: n.Value}
	}
	for _, x := range req.Extensions {
		p.Extensions = append(p.Extensions, string(x))
	}
	return p
}

// expand returns the samlidp.AuthnRequest that p keeps, and false if p is
// malformed.
func (p *payload) expand() (*samlidp.AuthnRequest, bool) {
	req := &samlidp.AuthnRequest{
		ID:                             p.ID,
		ServiceProvider:                p.ServiceProvider,
		RelayState:                     p.RelayState,
		ProviderName:                   p.ProviderName,
		AttributeConsumingServiceIndex: p.AttributeConsumingServiceIndex,
		ForceAuthn:                     p.ForceAuthn,
		IsPassive:                      p.IsPassive,
		SPNameQualifier:                p.SPNameQualifier,
		AllowCreate:                    p.AllowCreate,
		AuthnContextComparison:         saml.AuthnContextComparison(p.AuthnContextComparison),
		Signed:                         p.Signed,
	}
	if p.IssueInstant != 0 {
		req.IssueInstant = time.Unix(0, p.IssueInstant).UTC()
	}
	ok := true
	unsq := func(s string) string {
		v, good := unsqueeze(s)
		ok = ok && good
		return v
	}
	req.ACSURL = unsq(p.ACSURL)
	req.ACSBinding = unsq(p.ACSBinding)
	req.Consent = unsq(p.Consent)
	req.NameIDFormat = saml.NameIDFormat(unsq(p.NameIDFormat))
	classes, good := unsqueezeAll(p.AuthnContextClasses)
	ok = ok && good
	for _, c := range classes {
		req.AuthnContextClasses = append(req.AuthnContextClasses, saml.AuthnContextClass(c))
	}
	if len(p.AuthnContextDecls) > 0 {
		req.AuthnContextDecls = p.AuthnContextDecls
	}
	if s := p.Scoping; s != nil {
		req.Scoping = &saml.Scoping{ProxyCount: s.ProxyCount}
		if len(s.RequesterIDs) > 0 {
			req.Scoping.RequesterIDs = s.RequesterIDs
		}
		if s.HasIDPList {
			req.Scoping.IDPList = &saml.IDPList{GetComplete: s.GetComplete}
			for _, e := range s.IDPEntries {
				req.Scoping.IDPList.IDPEntries = append(req.Scoping.IDPList.IDPEntries,
					saml.IDPEntry{ProviderID: e.ProviderID, Name: e.Name, Loc: e.Loc})
			}
		}
	}
	if n := p.Subject; n != nil {
		req.Subject = &saml.NameID{NameQualifier: n.NameQualifier, SPNameQualifier: n.SPNameQualifier,
			Format: unsq(n.Format), SPProvidedID: n.SPProvidedID, Value: n.Value}
	}
	for _, x := range p.Extensions {
		req.Extensions = append(req.Extensions, []byte(x))
	}
	return req, ok
}
