package samlidp_test

import (
	"context"
	"crypto"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	dsig "github.com/russellhaering/goxmldsig"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlidp"
	"github.com/crewjam/saml/x/samlsp"
)

const artifactACS = "https://sp.example.com/saml/acs-artifact"

// artifactBinding is a samlidp.Binding for HTTP-Artifact that redirects to
// the ACS with a fixed artifact.
type artifactBinding struct{}

func (artifactBinding) URI() string { return saml.HTTPArtifactBinding }

func (artifactBinding) Encode(_ context.Context, m *samlidp.OutboundMessage) (*samlidp.Message, error) {
	u, err := url.Parse(m.Destination)
	if err != nil {
		return nil, err
	}
	u.RawQuery = url.Values{"SAMLart": {"artifact"}}.Encode()
	return m.Redirect(u), nil
}

// withArtifactACS makes the SP metadata list its HTTP-POST ACS, the
// default, and an HTTP-Artifact ACS at artifactACS.
func withArtifactACS(md *saml.EntityDescriptor) {
	d := &md.SPSSODescriptors[0]
	var acs []saml.IndexedEndpoint
	for _, ep := range d.AssertionConsumerServices {
		if ep.Binding == saml.HTTPPostBinding {
			acs = append(acs, ep)
		}
	}
	acs = append(acs, saml.IndexedEndpoint{
		Binding: saml.HTTPArtifactBinding, Location: artifactACS, Index: 9,
	})
	d.AssertionConsumerServices = acs
}

// An AuthnRequest that asks for the custom binding, and names no ACS,
// gets the SP's default ACS with that binding, not its default HTTP-POST
// ACS (saml-profiles §4.1.4.1).
func TestCustomBindingDefaultACS(t *testing.T) {
	p := newPairWithMetadata(t, nil, nil, withArtifactACS)
	ctx := context.Background()
	msg, err := p.sp.AuthnRequest(ctx, "rs", samlsp.WithAuthnRequest(func(req *saml.AuthnRequest) error {
		req.AssertionConsumerServiceURL = ""
		req.AssertionConsumerServiceIndex = ""
		req.ProtocolBinding = saml.HTTPArtifactBinding
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	custom := samlidp.WithCustomBinding(artifactBinding{})
	req, err := p.idp.ParseAuthnRequest(ctx, browserRequest(t, msg), custom)
	if err != nil {
		t.Fatal(err)
	}
	if req.ACSURL != artifactACS || req.ACSBinding != saml.HTTPArtifactBinding {
		t.Fatalf("ACS = %s %s, want %s %s", req.ACSBinding, req.ACSURL, saml.HTTPArtifactBinding, artifactACS)
	}
	resp, err := p.idp.Response(ctx, req, testSubject, custom)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Destination != artifactACS {
		t.Fatalf("Destination = %q", resp.Destination)
	}
}

// IDPInitiated with WithCustomBinding can choose an ACS with the custom
// binding: here the SP's only one.
func TestIDPInitiatedCustomBinding(t *testing.T) {
	p := newPairWithMetadata(t, nil, nil, func(md *saml.EntityDescriptor) {
		md.SPSSODescriptors[0].AssertionConsumerServices = []saml.IndexedEndpoint{{
			Binding: saml.HTTPArtifactBinding, Location: artifactACS, Index: 1,
		}}
	})
	ctx := context.Background()
	if _, err := p.idp.IDPInitiated(ctx, spEntityID, ""); !errors.Is(err, saml.ErrUnknownAssertionConsumerService) {
		t.Fatalf("without WithCustomBinding: got %v", err)
	}
	custom := samlidp.WithCustomBinding(artifactBinding{})
	req, err := p.idp.IDPInitiated(ctx, spEntityID, "/home", custom)
	if err != nil {
		t.Fatal(err)
	}
	if req.ACSURL != artifactACS || req.ACSBinding != saml.HTTPArtifactBinding || req.RelayState != "/home" {
		t.Fatalf("got %+v", req)
	}
	resp, err := p.idp.Response(ctx, req, testSubject, custom)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Destination != artifactACS {
		t.Fatalf("Destination = %q", resp.Destination)
	}

	// The checks of package saml still apply.
	if _, err := p.idp.IDPInitiated(ctx, "https://unknown.example.com", "", custom); !errors.Is(err, samlidp.ErrUnknownServiceProvider) {
		t.Fatalf("unknown SP: got %v", err)
	}
}

// fixedServiceProvider is a saml.ServiceProviderProvider that returns md.
type fixedServiceProvider struct{ md *saml.EntityDescriptor }

func (f fixedServiceProvider) GetServiceProvider(*http.Request, string) (*saml.EntityDescriptor, error) {
	return f.md, nil
}

// A ServiceProviderProvider set with an IdentityProviderOption does not
// make ParseAuthnRequest and IDPInitiated see other metadata than Response,
// which looks the SP up with the ServiceProviderFunc.
func TestServiceProviderProviderOption(t *testing.T) {
	keys(t)
	other := func(md *saml.EntityDescriptor) *saml.EntityDescriptor {
		cp := *md
		d := cp.SPSSODescriptors[0]
		d.AssertionConsumerServices = []saml.IndexedEndpoint{{Binding: saml.HTTPPostBinding, Location: "https://other.example.com/acs", Index: 1}}
		cp.SPSSODescriptors = []saml.SPSSODescriptor{d}
		return &cp
	}
	var p *pair
	override := samlidp.WithIdentityProvider(func(idp *saml.IdentityProvider) {
		if p != nil {
			idp.ServiceProviderProvider = fixedServiceProvider{other(p.sp.Metadata(context.Background()))}
		}
	})
	p = newPair(t, []samlidp.Option{override}, nil)
	ctx := context.Background()

	_, req, err := p.parse(t)
	if err != nil {
		t.Fatal(err)
	}
	if req.ACSURL != p.sp.ACSURL() {
		t.Fatalf("ParseAuthnRequest: ACSURL = %q", req.ACSURL)
	}
	if _, err := p.idp.Response(ctx, req, testSubject); err != nil {
		t.Fatal(err)
	}

	req, err = p.idp.IDPInitiated(ctx, spEntityID, "")
	if err != nil {
		t.Fatal(err)
	}
	if req.ACSURL != p.sp.ACSURL() {
		t.Fatalf("IDPInitiated: ACSURL = %q", req.ACSURL)
	}
	if _, err := p.idp.Response(ctx, req, testSubject); err != nil {
		t.Fatal(err)
	}
}

// The ForceAuthn check of Response allows the clock skew of an
// IdentityProviderOption passed to it.
func TestForceAuthnInstantPerCallClockSkew(t *testing.T) {
	p := newPair(t, nil, nil)
	_, req, err := p.parse(t, samlsp.ForceAuthn)
	if err != nil {
		t.Fatal(err)
	}
	subject := testSubject
	subject.AuthnInstant = req.IssueInstant.Add(-10 * time.Minute)
	skew := samlidp.WithIdentityProvider(func(idp *saml.IdentityProvider) { idp.MaxClockSkew = time.Hour })
	if _, err := p.idp.Response(context.Background(), req, subject, skew); err != nil {
		t.Fatal(err)
	}
}

// countingSigner counts the signatures it makes.
type countingSigner struct {
	crypto.Signer
	n atomic.Int32
}

func (s *countingSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.n.Add(1)
	return s.Signer.Sign(r, digest, opts)
}

// A request that ParseAuthnRequest refuses with a status costs one
// signature, that of the ErrorResponse that is sent.
func TestParseAuthnRequestErrorSignsOnce(t *testing.T) {
	p := newPair(t, nil, nil)
	ctx := context.Background()
	msg, err := p.sp.AuthnRequest(ctx, "rs")
	if err != nil {
		t.Fatal(err)
	}
	signer := &countingSigner{Signer: idpKey}
	later, err := samlidp.New(idpEntityID, samlidp.StaticServiceProviders(p.sp.Metadata(ctx)),
		samlidp.WithSigningKey(signer, idpCert), samlidp.WithClock(dsig.NewFakeClockAt(time.Now().Add(time.Hour))))
	if err != nil {
		t.Fatal(err)
	}
	req, err := later.ParseAuthnRequest(ctx, browserRequest(t, msg))
	status := asStatus(t, err, saml.StatusRequester, "")
	if n := signer.n.Load(); n != 0 {
		t.Fatalf("ParseAuthnRequest made %d signatures", n)
	}
	resp, err := later.ErrorResponse(ctx, req, status)
	if err != nil {
		t.Fatal(err)
	}
	if n := signer.n.Load(); n != 1 {
		t.Fatalf("made %d signatures, want 1", n)
	}
	if resp.InResponseTo != msg.ID {
		t.Fatalf("got %+v", resp)
	}
}
