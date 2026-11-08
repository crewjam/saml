package samlidp_test

import (
	"context"
	"encoding/xml"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	dsig "github.com/russellhaering/goxmldsig"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlidp"
	"github.com/crewjam/saml/x/samlsp"
)

// mdqServer is an MDQ service that serves the metadata in entities,
// counting requests by path.
type mdqServer struct {
	*httptest.Server
	hits     atomic.Int32
	accept   atomic.Value
	entities map[string]*saml.EntityDescriptor
}

func newMDQServer(t *testing.T, entities ...*saml.EntityDescriptor) *mdqServer {
	t.Helper()
	s := &mdqServer{entities: map[string]*saml.EntityDescriptor{}}
	for _, md := range entities {
		s.entities[md.EntityID] = md
	}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		s.accept.Store(r.Header.Get("Accept"))
		id, ok := strings.CutPrefix(r.URL.Path, "/mdq/entities/")
		md := s.entities[id]
		if !ok || md == nil {
			http.NotFound(w, r)
			return
		}
		buf, err := xml.Marshal(md)
		if err != nil {
			t.Error(err)
		}
		_, _ = w.Write(buf)
	}))
	t.Cleanup(s.Close)
	return s
}

func testSPMetadata(entityID string) *saml.EntityDescriptor {
	return &saml.EntityDescriptor{
		EntityID: entityID,
		SPSSODescriptors: []saml.SPSSODescriptor{{
			AssertionConsumerServices: []saml.IndexedEndpoint{{
				Binding:  saml.HTTPPostBinding,
				Location: entityID + "/acs",
			}},
		}},
	}
}

func TestMDQServiceProviders(t *testing.T) {
	const spID = "https://sp.example.com/saml/metadata?x=1"
	s := newMDQServer(t, testSPMetadata(spID))
	sps := samlidp.MDQServiceProviders(s.URL+"/mdq/", samlidp.WithHTTPClient(s.Client()))
	ctx := t.Context()

	for range 2 {
		md, err := sps(ctx, spID)
		if err != nil {
			t.Fatal(err)
		}
		if md.EntityID != spID {
			t.Fatalf("EntityID = %q", md.EntityID)
		}
	}
	if n := s.hits.Load(); n != 1 {
		t.Errorf("fetched %d times, want once", n)
	}
	if got := s.accept.Load(); got != "application/samlmetadata+xml" {
		t.Errorf("Accept = %q", got)
	}

	// An SP the service does not know is unknown, and the answer is kept.
	for range 2 {
		if _, err := sps(ctx, "https://unknown.example.com"); !errors.Is(err, samlidp.ErrUnknownServiceProvider) {
			t.Errorf("unknown SP: %v", err)
		}
	}
	if n := s.hits.Load(); n != 2 {
		t.Errorf("fetched %d times, want twice", n)
	}

	// An entityID too long to be one is unknown without a fetch.
	if _, err := sps(ctx, "https://"+strings.Repeat("a", 1024)); !errors.Is(err, samlidp.ErrUnknownServiceProvider) {
		t.Errorf("long entityID: %v", err)
	}
	if _, err := sps(ctx, ""); !errors.Is(err, samlidp.ErrUnknownServiceProvider) {
		t.Errorf("empty entityID: %v", err)
	}
	if n := s.hits.Load(); n != 2 {
		t.Errorf("fetched %d times, want twice", n)
	}
}

// TestMDQServiceProvidersChecks checks that MDQServiceProviders refuses
// metadata of another entity, of no SP, or that is expired, and fetches
// unsigned metadata only over https.
func TestMDQServiceProvidersChecks(t *testing.T) {
	other := testSPMetadata("https://other.example.com")
	idp := &saml.EntityDescriptor{EntityID: "https://idp.example.com", IDPSSODescriptors: []saml.IDPSSODescriptor{{}}}
	expired := testSPMetadata("https://expired.example.com")
	expired.ValidUntil = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	s := newMDQServer(t, idp, expired)
	s.entities["https://wrong.example.com"] = other
	sps := samlidp.MDQServiceProviders(s.URL+"/mdq", samlidp.WithHTTPClient(s.Client()))

	for _, id := range []string{"https://wrong.example.com", "https://idp.example.com"} {
		_, err := sps(t.Context(), id)
		if err == nil || errors.Is(err, samlidp.ErrUnknownServiceProvider) {
			t.Errorf("%s: %v", id, err)
		}
	}
	if _, err := sps(t.Context(), "https://expired.example.com"); !errors.Is(err, saml.ErrExpired) {
		t.Errorf("expired: %v", err)
	}
	// By the clock of WithClock, it is not expired.
	before := samlidp.WithClock(dsig.NewFakeClockAt(time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC)))
	if _, err := samlidp.MDQServiceProviders(s.URL+"/mdq", samlidp.WithHTTPClient(s.Client()), before)(t.Context(), "https://expired.example.com"); err != nil {
		t.Errorf("WithClock: %v", err)
	}

	plain := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(plain.Close)
	if _, err := samlidp.MDQServiceProviders(plain.URL)(t.Context(), "https://sp.example.com"); err == nil || !strings.Contains(err.Error(), "not an https URL") {
		t.Errorf("http URL: %v", err)
	}
}

// TestMDQServiceProvidersEviction checks that at most
// WithMaxCachedServiceProviders SPs are kept.
func TestMDQServiceProvidersEviction(t *testing.T) {
	a, b := testSPMetadata("https://a.example.com"), testSPMetadata("https://b.example.com")
	s := newMDQServer(t, a, b)
	sps := samlidp.MDQServiceProviders(s.URL+"/mdq", samlidp.WithHTTPClient(s.Client()), samlidp.WithMaxCachedServiceProviders(1))
	for _, id := range []string{a.EntityID, a.EntityID, b.EntityID, a.EntityID} {
		if _, err := sps(t.Context(), id); err != nil {
			t.Fatal(err)
		}
	}
	if n := s.hits.Load(); n != 3 {
		t.Errorf("fetched %d times, want 3", n)
	}
}

// TestMDQServiceProvidersSigned checks WithMetadataSigners: unsigned
// metadata is refused, and signed metadata is fetched over plain http.
func TestMDQServiceProvidersSigned(t *testing.T) {
	keys(t)
	ctx := context.Background()
	signedSP, err := samlsp.New(spEntityID, nil, samlsp.WithSigningKey(spKey, spCert), samlsp.SignMetadata)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signedSP.MetadataXML(ctx)
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := xml.Marshal(testSPMetadata(spEntityID))
	if err != nil {
		t.Fatal(err)
	}
	var body atomic.Value
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body.Load().([]byte))
	}))
	t.Cleanup(plain.Close)

	body.Store(unsigned)
	sps := samlidp.MDQServiceProviders(plain.URL, samlidp.WithHTTPClient(plain.Client()), samlidp.WithMetadataSigners(spCert))
	if _, err := sps(ctx, spEntityID); err == nil {
		t.Error("unsigned metadata accepted")
	}
	body.Store(signed)
	sps = samlidp.MDQServiceProviders(plain.URL, samlidp.WithHTTPClient(plain.Client()), samlidp.WithMetadataSigners(spCert))
	if _, err := sps(ctx, spEntityID); err != nil {
		t.Error(err)
	}
}

// TestMDQServiceProvidersConfig checks that a Config takes its SPs from
// MDQServiceProviders, and that its default client refuses a loopback
// address.
func TestMDQServiceProvidersConfig(t *testing.T) {
	keys(t)
	s := newMDQServer(t, testSPMetadata(spEntityID))
	c, err := samlidp.New(idpEntityID, samlidp.MDQServiceProviders(s.URL+"/mdq", samlidp.WithHTTPClient(s.Client())), samlidp.WithSigningKey(idpKey, idpCert))
	if err != nil {
		t.Fatal(err)
	}
	if md, err := c.ServiceProvider(t.Context(), spEntityID); err != nil || md.EntityID != spEntityID {
		t.Errorf("got %v, %v", md, err)
	}
	if _, err := c.ServiceProvider(t.Context(), "https://unknown.example.com"); !errors.Is(err, samlidp.ErrUnknownServiceProvider) {
		t.Errorf("unknown SP: %v", err)
	}

	_, err = samlidp.MDQServiceProviders(s.URL+"/mdq")(t.Context(), spEntityID)
	if err == nil || !strings.Contains(err.Error(), "not a permitted destination") {
		t.Errorf("default client: %v", err)
	}
}
