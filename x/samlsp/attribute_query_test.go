package samlsp_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/attrname"
	"github.com/crewjam/saml/x/samlsp"
)

// attributeAuthority answers attribute queries for ti, as its IdP would.
type attributeAuthority struct {
	*httptest.Server
	queried []string // the attribute Names of the last query
	sigAlg  string   // the signature method of the last query
	status  string
}

func newAttributeAuthority(t *testing.T, ti *testIDP) *attributeAuthority {
	t.Helper()
	aa := &attributeAuthority{status: saml.StatusSuccess}
	aa.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		doc := etree.NewDocument()
		if err := doc.ReadFromBytes(body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		query := doc.FindElement("//AttributeQuery")
		if query == nil || query.FindElement("./Signature") == nil {
			http.Error(w, "unsigned or missing query", http.StatusBadRequest)
			return
		}
		aa.sigAlg = ""
		if m := query.FindElement("./Signature/SignedInfo/SignatureMethod"); m != nil {
			aa.sigAlg = m.SelectAttrValue("Algorithm", "")
		}
		aa.queried = nil
		for _, a := range query.FindElements("./Attribute") {
			aa.queried = append(aa.queried, a.SelectAttrValue("Name", ""))
		}
		nameIDEl := query.FindElement("./Subject/NameID")

		now := time.Now().UTC()
		issuer := ti.idp.Metadata().EntityID
		resp := &saml.Response{
			ID: "id-aq-response", InResponseTo: query.SelectAttrValue("ID", ""),
			Version: "2.0", IssueInstant: now,
			Issuer: &saml.Issuer{Value: issuer},
			Status: saml.Status{StatusCode: saml.StatusCode{Value: aa.status}},
		}
		el := resp.Element()
		if aa.status == saml.StatusSuccess {
			assertion := &saml.Assertion{
				ID: "id-aq-assertion", IssueInstant: now, Version: "2.0",
				Issuer: saml.Issuer{Value: issuer},
				Subject: &saml.Subject{
					NameID: &saml.NameID{
						Format: nameIDEl.SelectAttrValue("Format", ""),
						Value:  nameIDEl.Text(),
					},
					SubjectConfirmations: []saml.SubjectConfirmation{{Method: "urn:oasis:names:tc:SAML:2.0:cm:sender-vouches"}},
				},
				Conditions: &saml.Conditions{
					NotBefore: now.Add(-time.Minute), NotOnOrAfter: now.Add(5 * time.Minute),
					AudienceRestrictions: []saml.AudienceRestriction{{Audience: saml.Audience{Value: spEntityID}}},
				},
				AttributeStatements: []saml.AttributeStatement{{Attributes: []saml.Attribute{
					{Name: attrname.Mail, NameFormat: attrname.FormatURI,
						Values: []saml.AttributeValue{{Type: "xs:string", Value: "alice@example.com"}}},
					{Name: attrname.EduPersonAffiliation, NameFormat: attrname.FormatURI,
						Values: []saml.AttributeValue{{Type: "xs:string", Value: "staff"}, {Type: "xs:string", Value: "member"}}},
				}}},
			}
			el.AddChild(assertion.Element())
		}
		signer := dsig.NewDefaultSigningContext(dsig.TLSCertKeyStore{PrivateKey: ti.key, Certificate: [][]byte{ti.cert.Raw}})
		signer.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
		if err := signer.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		signed, err := signer.SignEnveloped(el)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		out := etree.NewDocument()
		envelope := out.CreateElement("soapenv:Envelope")
		envelope.CreateAttr("xmlns:soapenv", "http://schemas.xmlsoap.org/soap/envelope/")
		envelope.CreateElement("soapenv:Body").AddChild(signed)
		w.Header().Set("Content-Type", "text/xml")
		_, _ = out.WriteTo(w)
	}))
	t.Cleanup(aa.Close)
	return aa
}

// withAttributeService returns ti's metadata with a SOAP AttributeService
// at location.
func withAttributeService(ti *testIDP, location string) samlsp.MetadataFunc {
	return func(context.Context) (*saml.EntityDescriptor, error) {
		md := ti.idp.Metadata()
		md.AttributeAuthorityDescriptors = []saml.AttributeAuthorityDescriptor{{
			RoleDescriptor:    saml.RoleDescriptor{ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol"},
			AttributeServices: []saml.Endpoint{{Binding: saml.SOAPBinding, Location: location}},
		}}
		return md, nil
	}
}

func TestQueryAttributes(t *testing.T) {
	ti := newTestIDP(t)
	aa := newAttributeAuthority(t, ti)
	cfg := newTestConfigWithIDP(t, ti, withAttributeService(ti, aa.URL), samlsp.WithHTTPClient(aa.Client()))
	ctx := t.Context()
	alice := saml.NameID{Format: string(saml.EmailAddressNameIDFormat), Value: "alice@example.com"}

	attrs, err := cfg.QueryAttributes(ctx, alice,
		samlsp.WithQueriedAttributes(attrname.Mail, attrname.EduPersonAffiliation))
	if err != nil {
		t.Fatalf("QueryAttributes: %v (%v)", err, errors.Unwrap(err))
	}
	if len(aa.queried) != 2 {
		t.Errorf("queried %v", aa.queried)
	}
	var user struct {
		Mail        string   `saml:"urn:oid:0.9.2342.19200300.100.1.3"`
		Affiliation []string `saml:"urn:oid:1.3.6.1.4.1.5923.1.1.1.1"`
	}
	if err := attrs.Decode(&user); err != nil {
		t.Fatal(err)
	}
	if user.Mail != "alice@example.com" || len(user.Affiliation) != 2 {
		t.Errorf("decoded %+v from %+v", user, attrs)
	}

	// The IdP refuses.
	aa.status = saml.StatusRequester
	var status saml.ErrBadStatus
	if _, err := cfg.QueryAttributes(ctx, alice); !errors.As(err, &status) {
		t.Errorf("err = %v, want ErrBadStatus", err)
	}

	// No AttributeService.
	plain := newTestConfig(t, ti)
	if _, err := plain.QueryAttributes(ctx, alice); !errors.Is(err, samlsp.ErrNoEndpoint) {
		t.Errorf("err = %v, want ErrNoEndpoint", err)
	}
}
