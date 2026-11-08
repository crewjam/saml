package idpartifact_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	dsig "github.com/russellhaering/goxmldsig"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlidp"
	"github.com/crewjam/saml/x/samlidp/idpartifact"
	"github.com/crewjam/saml/x/samlsp"
)

const idpEntityID = "https://idp.example.com/saml/metadata"

var (
	keysOnce sync.Once
	keyPairs [3]struct {
		key  *rsa.PrivateKey
		cert *x509.Certificate
	}
	keysErr error
)

// keyPair returns test key pair i (0: the IdP, 1 and 2: the SPs).
func keyPair(t *testing.T, i int) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	keysOnce.Do(func() {
		for i := range keyPairs {
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				keysErr = err
				return
			}
			tmpl := &x509.Certificate{
				SerialNumber: big.NewInt(int64(i + 1)),
				Subject:      pkix.Name{CommonName: "test"},
				NotBefore:    time.Now().Add(-time.Hour),
				NotAfter:     time.Now().Add(24 * time.Hour),
			}
			der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
			if err != nil {
				keysErr = err
				return
			}
			if keyPairs[i].cert, err = x509.ParseCertificate(der); err != nil {
				keysErr = err
				return
			}
			keyPairs[i].key = key
		}
	})
	if keysErr != nil {
		t.Fatal(keysErr)
	}
	return keyPairs[i].key, keyPairs[i].cert
}

// world is an IdP whose ArtifactResolutionService is a TLS test server,
// and two SPs of x/samlsp.
type world struct {
	idp     *samlidp.Config
	binding *idpartifact.Binding
	store   *idpartifact.MemoryStore
	server  *httptest.Server
	sps     [2]*samlsp.Config
}

func newWorld(t *testing.T, configure func(*idpartifact.Binding)) *world {
	t.Helper()
	w := &world{store: idpartifact.NewMemoryStore()}
	w.server = httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		w.binding.ServeHTTP(rw, r)
	}))
	t.Cleanup(w.server.Close)

	idpMetadata := func(context.Context) (*saml.EntityDescriptor, error) { return w.idp.Metadata(), nil }
	mds := make([]*saml.EntityDescriptor, 0, len(w.sps))
	for i := range w.sps {
		key, cert := keyPair(t, i+1)
		base := "https://sp" + string(rune('1'+i)) + ".example.com"
		sp, err := samlsp.New(base+"/saml/metadata", idpMetadata,
			samlsp.WithSigningKey(key, cert), samlsp.WithHTTPClient(w.server.Client()), samlsp.AcceptArtifactResponses)
		if err != nil {
			t.Fatal(err)
		}
		w.sps[i] = sp
		mds = append(mds, sp.Metadata(context.Background()))
	}
	key, cert := keyPair(t, 0)
	var err error
	w.idp, err = samlidp.New(idpEntityID, samlidp.StaticServiceProviders(mds...), samlidp.WithSigningKey(key, cert),
		idpartifact.ResolutionService(w.server.URL+"/saml/artifact", 3))
	if err != nil {
		t.Fatal(err)
	}
	w.binding = newBinding(t, w.idp, w.store, 3)
	if configure != nil {
		configure(w.binding)
	}
	return w
}

var subject = samlidp.Subject{
	NameID:       "alice",
	AuthnInstant: time.Now(),
	SessionIndex: "s1",
	Attributes:   []samlidp.Attribute{{Name: "mail", Values: []string{"alice@example.com"}}},
}

// start sends an AuthnRequest of SP 1 that asks for the artifact binding
// to the IdP, which parses it with the artifact binding.
func (w *world) start(t *testing.T, opts ...samlsp.AuthnOption) (*samlsp.Message, *samlidp.AuthnRequest) {
	t.Helper()
	opts = append([]samlsp.AuthnOption{samlsp.WithResponseBinding(saml.HTTPArtifactBinding)}, opts...)
	msg, err := w.sps[0].AuthnRequest(context.Background(), "relay", opts...)
	if err != nil {
		t.Fatal(err)
	}
	req, err := w.idp.ParseAuthnRequest(context.Background(),
		httptest.NewRequest(http.MethodGet, msg.RedirectURL().String(), http.NoBody), samlidp.WithCustomBinding(w.binding))
	if err != nil {
		t.Fatal(err)
	}
	return msg, req
}

// arrive returns the request with which the browser brings msg to the SP.
func arrive(t *testing.T, msg *samlidp.Message) *http.Request {
	t.Helper()
	if u := msg.RedirectURL(); u != nil {
		return httptest.NewRequest(http.MethodGet, u.String(), http.NoBody)
	}
	fields := url.Values{}
	for k, v := range msg.FormValues() {
		fields.Set(k, v)
	}
	r := httptest.NewRequest(http.MethodPost, msg.Destination, strings.NewReader(fields.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

func TestLogin(t *testing.T) {
	for _, form := range []bool{false, true} {
		t.Run(map[bool]string{false: "redirect", true: "form"}[form], func(t *testing.T) {
			w := newWorld(t, func(b *idpartifact.Binding) { b.Form = form })
			ctx := context.Background()
			msg, req := w.start(t)
			if req.ACSBinding != saml.HTTPArtifactBinding || req.ACSURL != w.sps[0].ACSURL() {
				t.Fatalf("ACS %s %s", req.ACSBinding, req.ACSURL)
			}
			resp, err := w.idp.Response(ctx, req, subject, samlidp.WithCustomBinding(w.binding))
			if err != nil {
				t.Fatal(err)
			}
			if resp.Binding != saml.HTTPArtifactBinding || resp.Participant == nil || resp.InResponseTo != msg.ID {
				t.Fatalf("got %+v", resp)
			}
			if form {
				if resp.RedirectURL() != nil || resp.FormValues()["SAMLart"] == "" || resp.FormValues()["RelayState"] != "relay" {
					t.Fatalf("form %v", resp.FormValues())
				}
			} else {
				u := resp.RedirectURL()
				if u == nil || u.Query().Get("SAMLart") == "" || u.Query().Get("RelayState") != "relay" {
					t.Fatalf("redirect %v", u)
				}
				if strings.Contains(u.String(), "alice") {
					t.Fatal("the assertion is in the URL")
				}
			}
			if w.store.Len() != 1 {
				t.Fatalf("%d stored", w.store.Len())
			}
			a, err := w.sps[0].ParseResponse(ctx, arrive(t, resp), samlsp.WithRequestID(msg.ID))
			if err != nil {
				t.Fatal(err)
			}
			if a.Subject != "alice" || a.Attributes.Get("mail") != "alice@example.com" {
				t.Fatalf("got %+v", a)
			}
			if w.store.Len() != 0 {
				t.Fatal("the message was kept after it was resolved")
			}
		})
	}
}

func TestErrorResponse(t *testing.T) {
	w := newWorld(t, nil)
	ctx := context.Background()
	msg, req := w.start(t, samlsp.IsPassive)
	resp, err := w.idp.ErrorResponse(ctx, req, &saml.StatusError{TopLevel: saml.StatusResponder, SecondLevel: saml.StatusNoPassive},
		samlidp.WithCustomBinding(w.binding))
	if err != nil {
		t.Fatal(err)
	}
	if resp.RedirectURL() == nil {
		t.Fatalf("not sent by artifact: %+v", resp)
	}
	_, err = w.sps[0].ParseResponse(ctx, arrive(t, resp), samlsp.WithRequestID(msg.ID))
	var bad saml.ErrBadStatus
	if !errors.As(err, &bad) || bad.Status != saml.StatusResponder {
		t.Fatalf("got %v", err)
	}
}

func TestResolvedOnce(t *testing.T) {
	w := newWorld(t, nil)
	ctx := context.Background()
	msg, req := w.start(t)
	resp, err := w.idp.Response(ctx, req, subject, samlidp.WithCustomBinding(w.binding))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.sps[0].ParseResponse(ctx, arrive(t, resp), samlsp.WithRequestID(msg.ID)); err != nil {
		t.Fatal(err)
	}
	// A second SP process, with its own replay record, cannot have the
	// Response again.
	key, cert := keyPair(t, 1)
	again, err := samlsp.New(w.sps[0].EntityID(), func(context.Context) (*saml.EntityDescriptor, error) { return w.idp.Metadata(), nil },
		samlsp.WithSigningKey(key, cert), samlsp.WithHTTPClient(w.server.Client()), samlsp.AcceptArtifactResponses)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := again.ParseResponse(ctx, arrive(t, resp), samlsp.WithRequestID(msg.ID)); err == nil {
		t.Fatal("the artifact was resolved twice")
	}
}

func TestOtherSPCannotResolve(t *testing.T) {
	w := newWorld(t, nil)
	ctx := context.Background()
	msg, req := w.start(t)
	resp, err := w.idp.Response(ctx, req, subject, samlidp.WithCustomBinding(w.binding))
	if err != nil {
		t.Fatal(err)
	}
	// SP 2 gets the artifact (say, from a log) and tries to resolve it.
	r := arrive(t, resp)
	r.URL.Host = "sp2.example.com"
	if _, err := w.sps[1].ParseResponse(ctx, r, samlsp.AllowUnsolicited, samlsp.WithRequestID(msg.ID)); err == nil {
		t.Fatal("SP 2 resolved the artifact of SP 1")
	}
	// It is still there for SP 1.
	if _, err := w.sps[0].ParseResponse(ctx, arrive(t, resp), samlsp.WithRequestID(msg.ID)); err != nil {
		t.Fatal(err)
	}
}

func TestExpired(t *testing.T) {
	w := newWorld(t, func(b *idpartifact.Binding) { b.Lifetime = time.Nanosecond })
	ctx := context.Background()
	msg, req := w.start(t)
	resp, err := w.idp.Response(ctx, req, subject, samlidp.WithCustomBinding(w.binding))
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond)
	if _, err := w.sps[0].ParseResponse(ctx, arrive(t, resp), samlsp.WithRequestID(msg.ID)); err == nil {
		t.Fatal("an expired artifact was resolved")
	}
}

func TestUnsignedResolveRefused(t *testing.T) {
	w := newWorld(t, nil)
	body := `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body>` +
		`<samlp:ArtifactResolve xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"` +
		` ID="id-1" Version="2.0" IssueInstant="` + time.Now().UTC().Format(time.RFC3339) + `">` +
		`<saml:Issuer>` + w.sps[0].EntityID() + `</saml:Issuer><samlp:Artifact>AAQAAA==</samlp:Artifact>` +
		`</samlp:ArtifactResolve></soapenv:Body></soapenv:Envelope>`
	for _, r := range []*http.Request{
		httptest.NewRequest(http.MethodPost, "/saml/artifact", strings.NewReader(body)),
		httptest.NewRequest(http.MethodGet, "/saml/artifact", http.NoBody),
	} {
		r.Header.Set("Content-Type", "text/xml")
		rec := httptest.NewRecorder()
		w.binding.ServeHTTP(rec, r)
		if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "Fault") {
			t.Errorf("%s: got %d %s", r.Method, rec.Code, rec.Body.String())
		}
	}
}

func TestWithoutCustomBinding(t *testing.T) {
	w := newWorld(t, nil)
	ctx := context.Background()

	// By URL: the SP's HTTP-POST ACS at the same URL is used.
	msg, err := w.sps[0].AuthnRequest(ctx, "", samlsp.WithResponseBinding(saml.HTTPArtifactBinding))
	if err != nil {
		t.Fatal(err)
	}
	req, err := w.idp.ParseAuthnRequest(ctx, httptest.NewRequest(http.MethodGet, msg.RedirectURL().String(), http.NoBody))
	if err != nil {
		t.Fatal(err)
	}
	if req.ACSBinding != saml.HTTPPostBinding {
		t.Fatalf("ACSBinding = %q", req.ACSBinding)
	}

	// By index: the artifact ACS cannot be used.
	idx := -1
	for _, acs := range w.sps[0].Metadata(ctx).SPSSODescriptors[0].AssertionConsumerServices {
		if acs.Binding == saml.HTTPArtifactBinding {
			idx = acs.Index
		}
	}
	msg, err = w.sps[0].AuthnRequest(ctx, "", samlsp.WithACSIndex(idx))
	if err != nil {
		t.Fatal(err)
	}
	r := func() *http.Request {
		return httptest.NewRequest(http.MethodGet, msg.RedirectURL().String(), http.NoBody)
	}
	_, err = w.idp.ParseAuthnRequest(ctx, r())
	var status *saml.StatusError
	if !errors.As(err, &status) || status.SecondLevel != saml.StatusUnsupportedBinding {
		t.Fatalf("got %v", err)
	}
	req, err = w.idp.ParseAuthnRequest(ctx, r(), samlidp.WithCustomBinding(w.binding))
	if err != nil {
		t.Fatal(err)
	}
	if req.ACSBinding != saml.HTTPArtifactBinding {
		t.Fatalf("ACSBinding = %q", req.ACSBinding)
	}
	if _, err := w.idp.Response(ctx, req, subject); err == nil {
		t.Fatal("Response without WithCustomBinding sent to an artifact ACS")
	}
}

func TestMetadata(t *testing.T) {
	w := newWorld(t, nil)
	ars := w.idp.Metadata().IDPSSODescriptors[0].SSODescriptor.ArtifactResolutionServices
	if len(ars) != 1 || ars[0].Binding != saml.SOAPBinding || ars[0].Index != 3 || ars[0].Location != w.server.URL+"/saml/artifact" {
		t.Fatalf("ArtifactResolutionServices = %+v", ars)
	}
	if w.binding.Path() != "/saml/artifact" {
		t.Errorf("Path = %q", w.binding.Path())
	}
	// An index the metadata does not advertise is refused, rather than
	// making artifacts that cannot be resolved and an empty Path.
	if _, err := idpartifact.New(w.idp, w.store, 9); err == nil || !strings.Contains(err.Error(), "index 9") {
		t.Errorf("New with an unknown index: %v", err)
	}
	key, cert := keyPair(t, 0)
	if _, err := samlidp.New(idpEntityID, samlidp.StaticServiceProviders(), samlidp.WithSigningKey(key, cert),
		idpartifact.ResolutionService("/relative", 1)); err == nil {
		t.Error("relative URL: no error")
	}
}

// newBinding returns the Binding of New, failing t on an error.
func newBinding(t *testing.T, config *samlidp.Config, store idpartifact.Store, index uint16) *idpartifact.Binding {
	t.Helper()
	b, err := idpartifact.New(config, store, index)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestMemoryStoreClock checks that New gives a MemoryStore with no Now
// the clock of samlidp.WithClock, by which the Binding sets ExpiresAt: a
// message stored by a clock set in the past is kept for its lifetime, not
// forgotten at once by the system clock.
func TestMemoryStoreClock(t *testing.T) {
	past := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := dsig.NewFakeClockAt(past)
	key, cert := keyPair(t, 0)
	config, err := samlidp.New(idpEntityID, samlidp.StaticServiceProviders(), samlidp.WithSigningKey(key, cert),
		samlidp.WithClock(clock), idpartifact.ResolutionService("https://idp.example.com/saml/artifact", 1))
	if err != nil {
		t.Fatal(err)
	}
	store := idpartifact.NewMemoryStore()
	newBinding(t, config, store, 1)
	if store.Now == nil || !store.Now().Equal(config.Now()) {
		t.Fatal("New did not set the store's Now to config.Now")
	}
	if err := store.Save(context.Background(), "a", idpartifact.StoredMessage{ExpiresAt: config.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if store.Len() != 1 {
		t.Error("the message expired by the system clock")
	}
}

// New may be given a MemoryStore that is already in use, such as one
// shared with another Binding: it sets the store's clock under its lock.
// Run with -race.
func TestNewWithStoreInUse(t *testing.T) {
	w := newWorld(t, nil)
	store := idpartifact.NewMemoryStore()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range 50 {
			_ = store.Save(context.Background(), fmt.Sprint(i), idpartifact.StoredMessage{ExpiresAt: time.Now().Add(time.Minute)})
		}
	}()
	if _, err := idpartifact.New(w.idp, store, 3); err != nil {
		t.Fatal(err)
	}
	<-done
}
