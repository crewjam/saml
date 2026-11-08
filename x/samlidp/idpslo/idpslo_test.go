package idpslo_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlidp"
	"github.com/crewjam/saml/x/samlidp/idpslo"
	"github.com/crewjam/saml/x/samlsp"
	"github.com/crewjam/saml/x/samlsp/slo"
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
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				keysErr = err
				return
			}
			keyPairs[i].key, keyPairs[i].cert = key, cert
		}
	})
	if keysErr != nil {
		t.Fatal(keysErr)
	}
	return keyPairs[i].key, keyPairs[i].cert
}

// sp is a service provider of x/samlsp with single logout.
type sp struct {
	config *samlsp.Config
	slo    *slo.Service
}

// world is an IdP and two SPs that trust each other.
type world struct {
	idp    *samlidp.Config
	logout *idpslo.Service
	sps    [2]*sp
}

type worldOptions struct {
	idp       []idpslo.EndpointOption
	idpConfig []samlidp.Option
	sp        [2][]slo.EndpointOption
	spConfig  [2][]samlsp.Option
	// spBase and idpSLO, if set, are the base URL of each SP and the IdP's
	// SLO URL, such as those of TLS test servers.
	spBase [2]string
	idpSLO string
}

func newWorld(t *testing.T, o worldOptions) *world {
	t.Helper()
	w := &world{}
	idpMetadata := func(context.Context) (*saml.EntityDescriptor, error) { return w.idp.Metadata(), nil }
	mds := make([]*saml.EntityDescriptor, 0, len(w.sps))
	for i := range w.sps {
		key, cert := keyPair(t, i+1)
		base := o.spBase[i]
		if base == "" {
			base = "https://sp" + string(rune('1'+i)) + ".example.com"
		}
		opts := append([]samlsp.Option{
			samlsp.WithSigningKey(key, cert),
			slo.Endpoint(base+"/saml/slo", o.sp[i]...),
		}, o.spConfig[i]...)
		config, err := samlsp.New(base+"/saml/metadata", idpMetadata, opts...)
		if err != nil {
			t.Fatal(err)
		}
		logout, err := slo.New(config)
		if err != nil {
			t.Fatal(err)
		}
		w.sps[i] = &sp{config, logout}
		mds = append(mds, config.Metadata(context.Background()))
	}
	key, cert := keyPair(t, 0)
	sloURL := o.idpSLO
	if sloURL == "" {
		sloURL = "https://idp.example.com/saml/slo"
	}
	opts := append([]samlidp.Option{
		samlidp.WithSigningKey(key, cert),
		idpslo.Endpoint(sloURL, o.idp...),
	}, o.idpConfig...)
	var err error
	w.idp, err = samlidp.New(idpEntityID, samlidp.StaticServiceProviders(mds...), opts...)
	if err != nil {
		t.Fatal(err)
	}
	if w.logout, err = idpslo.New(w.idp); err != nil {
		t.Fatal(err)
	}
	return w
}

// login logs the user in to SP i and returns the participant the IdP
// records, and the assertion the SP gets.
func (w *world) login(t *testing.T, i int, sessionIndex string) (saml.SessionParticipant, *samlsp.Assertion) {
	t.Helper()
	ctx := context.Background()
	s := w.sps[i]
	msg, err := s.config.AuthnRequest(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	req, err := w.idp.ParseAuthnRequest(ctx, toIDP(t, msg))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := w.idp.Response(ctx, req, samlidp.Subject{
		NameID:       "alice",
		NameIDFormat: saml.TransientNameIDFormat,
		AuthnInstant: time.Now(),
		SessionIndex: sessionIndex,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Participant == nil {
		t.Fatal("no Participant")
	}
	a, err := s.config.ParseResponse(ctx, deliver(t, resp), samlsp.WithRequestID(msg.ID))
	if err != nil {
		t.Fatal(err)
	}
	if a.NameID != resp.Participant.NameID || a.SessionIndexes[0] != resp.Participant.SessionIndex {
		t.Fatalf("participant %+v, assertion %+v", resp.Participant, a.NameID)
	}
	return *resp.Participant, a
}

// toIDP returns the http.Request with which the browser delivers msg, from
// an SP, to the IdP.
func toIDP(t *testing.T, msg *samlsp.Message) *http.Request {
	t.Helper()
	if u := msg.RedirectURL(); u != nil {
		return httptest.NewRequest(http.MethodGet, u.String(), http.NoBody)
	}
	return post(msg.Destination, formOf(t, msg))
}

// deliver returns the http.Request with which the browser delivers msg,
// from the IdP, to an SP.
func deliver(t *testing.T, msg *samlidp.Message) *http.Request {
	t.Helper()
	if u := msg.RedirectURL(); u != nil {
		return httptest.NewRequest(http.MethodGet, u.String(), http.NoBody)
	}
	fields := url.Values{}
	for k, v := range msg.FormValues() {
		fields.Set(k, v)
	}
	if len(fields) == 0 {
		t.Fatalf("message %+v is neither a redirect nor a form", msg)
	}
	return post(msg.Destination, fields)
}

func post(target string, fields url.Values) *http.Request {
	r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(fields.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

// formOf returns the fields of the form that h writes.
func formOf(t *testing.T, h http.Handler) url.Values {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", http.NoBody))
	fields := url.Values{}
	for _, part := range strings.Split(rec.Body.String(), "<input ")[1:] {
		if !strings.Contains(part, `type="hidden"`) {
			continue
		}
		value := between(part, `value="`, `"`)
		value = strings.NewReplacer("&#43;", "+", "&#61;", "=", "&amp;", "&", "&#34;", `"`, "&#39;", "'", "&lt;", "<", "&gt;", ">").Replace(value)
		fields.Add(between(part, `name="`, `"`), value)
	}
	if len(fields) == 0 {
		t.Fatalf("no form in %s", rec.Body.String())
	}
	return fields
}

func between(s, start, end string) string {
	_, rest, _ := strings.Cut(s, start)
	v, _, _ := strings.Cut(rest, end)
	return v
}

// TestSPInitiated runs a logout that SP 1 starts: the IdP logs the user out
// of SP 2 through the browser, then answers SP 1.
func TestSPInitiated(t *testing.T) {
	for _, binding := range []string{saml.HTTPRedirectBinding, saml.HTTPPostBinding} {
		t.Run(binding, func(t *testing.T) {
			ctx := context.Background()
			w := newWorld(t, worldOptions{})
			p1, a1 := w.login(t, 0, "s1")
			p2, _ := w.login(t, 1, "s1")

			// SP 1 starts the logout.
			sp1 := w.sps[0]
			out, err := sp1.slo.Request(ctx, a1.NameID, "sp1-relay", slo.WithSessionIndex(a1.SessionIndexes...), samlsp.WithBinding(binding))
			if err != nil {
				t.Fatal(err)
			}
			req, err := w.logout.ParseRequest(ctx, toIDP(t, out))
			if err != nil {
				t.Fatal(err)
			}
			if req.ServiceProvider != sp1.config.EntityID() || req.NameID.Value != "alice" || req.RelayState != "sp1-relay" || req.Binding != binding {
				t.Fatalf("got %+v", req)
			}
			if !req.Matches(p1) || req.Matches(p2) {
				t.Fatalf("Matches: %v %v", req.Matches(p1), req.Matches(p2))
			}

			// The IdP keeps the request while it visits SP 2.
			buf, err := json.Marshal(req)
			if err != nil {
				t.Fatal(err)
			}
			var kept idpslo.Request
			if err := json.Unmarshal(buf, &kept); err != nil {
				t.Fatal(err)
			}

			toSP2, err := w.logout.Request(ctx, p2, "step-2", idpslo.WithReason(saml.LogoutReasonUser), idpslo.WithBinding(binding))
			if err != nil {
				t.Fatal(err)
			}
			if toSP2.Binding != binding {
				t.Fatalf("Binding = %q", toSP2.Binding)
			}
			sp2 := w.sps[1]
			sp2req, err := sp2.slo.ParseRequest(ctx, deliver(t, toSP2))
			if err != nil {
				t.Fatal(err)
			}
			if sp2req.NameID.Value != "alice" || len(sp2req.SessionIndexes) != 1 || sp2req.SessionIndexes[0] != "s1" || sp2req.RelayState != "step-2" {
				t.Fatalf("SP 2 got %+v", sp2req)
			}
			sp2resp, err := sp2.slo.Response(ctx, sp2req)
			if err != nil {
				t.Fatal(err)
			}
			back := toIDP(t, sp2resp)
			if !idpslo.IsResponse(back) || idpslo.IsRequest(back) {
				t.Fatal("the answer of SP 2 is not a response")
			}
			if _, err := w.logout.ParseResponse(ctx, back, sp2.config.EntityID(), toSP2.ID); err != nil {
				t.Fatal(err)
			}

			// Then answer SP 1.
			msg, err := w.logout.Response(ctx, &kept)
			if err != nil {
				t.Fatal(err)
			}
			if msg.InResponseTo != out.ID || msg.RelayState != "sp1-relay" {
				t.Fatalf("got %+v", msg)
			}
			resp, err := sp1.slo.ParseResponse(ctx, deliver(t, msg), out.ID)
			if err != nil {
				t.Fatal(err)
			}
			if resp.Status.StatusCode.Value != saml.StatusSuccess {
				t.Fatalf("status %+v", resp.Status)
			}
		})
	}
}

func TestPartialLogout(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t, worldOptions{})
	_, a1 := w.login(t, 0, "s1")
	out, err := w.sps[0].slo.Request(ctx, a1.NameID, "")
	if err != nil {
		t.Fatal(err)
	}
	req, err := w.logout.ParseRequest(ctx, toIDP(t, out))
	if err != nil {
		t.Fatal(err)
	}
	msg, err := w.logout.Response(ctx, req, idpslo.PartialLogout)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := w.sps[0].slo.ParseResponse(ctx, deliver(t, msg), out.ID)
	if !errors.Is(err, slo.ErrPartialLogout) || resp == nil {
		t.Fatalf("got %v, %v", resp, err)
	}
	if s := resp.Status.StatusCode.StatusCode; s == nil || s.Value != saml.StatusPartialLogout {
		t.Fatalf("status %+v", resp.Status)
	}
}

func TestReplay(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t, worldOptions{})
	_, a1 := w.login(t, 0, "s1")
	out, err := w.sps[0].slo.Request(ctx, a1.NameID, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.logout.ParseRequest(ctx, toIDP(t, out)); err != nil {
		t.Fatal(err)
	}
	if _, err := w.logout.ParseRequest(ctx, toIDP(t, out)); !errors.Is(err, saml.ErrAssertionReplayed) {
		t.Fatalf("replayed: got %v", err)
	}
}

// recordingState is a ReplayState that keeps every key it is given.
type recordingState struct {
	mu   sync.Mutex
	keys map[string]bool
}

func (s *recordingState) Consume(_ context.Context, key []byte, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.keys[string(key)] {
		return saml.ErrAssertionReplayed
	}
	s.keys[string(key)] = true
	return nil
}

func (s *recordingState) has(key []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.keys[string(key)]
}

// TestReplayKeys checks the keys under which logout messages are recorded,
// as samlsp.ReplayKey and samlidp.ReplayKey document them.
func TestReplayKeys(t *testing.T) {
	ctx := context.Background()
	state := &recordingState{keys: map[string]bool{}}
	w := newWorld(t, worldOptions{
		idpConfig: []samlidp.Option{samlidp.WithReplayState(state)},
		spConfig:  [2][]samlsp.Option{{samlsp.WithReplayState(state)}, {samlsp.WithReplayState(state)}},
	})
	sp1, sp2 := w.sps[0], w.sps[1]

	// Logout started by SP 1.
	_, a1 := w.login(t, 0, "s1")
	out, err := sp1.slo.Request(ctx, a1.NameID, "")
	if err != nil {
		t.Fatal(err)
	}
	req, err := w.logout.ParseRequest(ctx, toIDP(t, out))
	if err != nil {
		t.Fatal(err)
	}
	if !state.has(samlidp.ReplayKey(sp1.config.EntityID(), "LogoutRequest:"+out.ID)) {
		t.Error("the IdP did not record the LogoutRequest")
	}
	back, err := w.logout.Response(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := sp1.slo.ParseResponse(ctx, deliver(t, back), out.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !state.has(samlsp.ReplayKey(idpEntityID, "LogoutResponse:"+resp.ID)) {
		t.Error("the SP did not record the LogoutResponse")
	}

	// Logout of SP 2 started by the IdP.
	p2, _ := w.login(t, 1, "s1")
	toSP2, err := w.logout.Request(ctx, p2, "")
	if err != nil {
		t.Fatal(err)
	}
	sp2req, err := sp2.slo.ParseRequest(ctx, deliver(t, toSP2))
	if err != nil {
		t.Fatal(err)
	}
	if !state.has(samlsp.ReplayKey(idpEntityID, "LogoutRequest:"+toSP2.ID)) {
		t.Error("the SP did not record the LogoutRequest")
	}
	answer, err := sp2.slo.Response(ctx, sp2req)
	if err != nil {
		t.Fatal(err)
	}
	resp, err = w.logout.ParseResponse(ctx, toIDP(t, answer), sp2.config.EntityID(), toSP2.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !state.has(samlidp.ReplayKey(sp2.config.EntityID(), "LogoutResponse:"+resp.ID)) {
		t.Error("the IdP did not record the LogoutResponse")
	}
}

func TestBadResponses(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t, worldOptions{})
	p2, _ := w.login(t, 1, "s1")
	toSP2, err := w.logout.Request(ctx, p2, "")
	if err != nil {
		t.Fatal(err)
	}
	sp2 := w.sps[1]
	sp2req, err := sp2.slo.ParseRequest(ctx, deliver(t, toSP2))
	if err != nil {
		t.Fatal(err)
	}
	refused, err := sp2.slo.Response(ctx, sp2req, slo.WithStatus(saml.Status{StatusCode: saml.StatusCode{Value: saml.StatusResponder}}))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := w.logout.ParseResponse(ctx, toIDP(t, refused), sp2.config.EntityID(), toSP2.ID)
	var bad saml.ErrBadStatus
	if !errors.As(err, &bad) || bad.Status != saml.StatusResponder || resp == nil {
		t.Fatalf("got %v, %v", resp, err)
	}

	ok, err := sp2.slo.Response(ctx, sp2req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.logout.ParseResponse(ctx, toIDP(t, ok), sp2.config.EntityID(), "id-other"); err == nil {
		t.Error("a response to another request was accepted")
	}
	if _, err := w.logout.ParseResponse(ctx, toIDP(t, ok), w.sps[0].config.EntityID(), toSP2.ID); err == nil {
		t.Error("a response from another SP was accepted")
	}
	if _, err := w.logout.ParseResponse(ctx, toIDP(t, ok), sp2.config.EntityID()); !errors.Is(err, idpslo.ErrNoRequestID) {
		t.Errorf("no request ID: got %v", err)
	}
	if _, err := w.logout.ParseResponse(ctx, toIDP(t, ok), sp2.config.EntityID(), toSP2.ID); err != nil {
		t.Fatal(err)
	}
}

// partialStatus is the status of an SP that logged the user out only in
// part.
var partialStatus = saml.Status{StatusCode: saml.StatusCode{
	Value:      saml.StatusSuccess,
	StatusCode: &saml.StatusCode{Value: saml.StatusPartialLogout},
}}

func TestParseResponsePartialLogout(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t, worldOptions{})
	p2, _ := w.login(t, 1, "s1")
	toSP2, err := w.logout.Request(ctx, p2, "")
	if err != nil {
		t.Fatal(err)
	}
	sp2 := w.sps[1]
	sp2req, err := sp2.slo.ParseRequest(ctx, deliver(t, toSP2))
	if err != nil {
		t.Fatal(err)
	}
	partial, err := sp2.slo.Response(ctx, sp2req, slo.WithStatus(partialStatus))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := w.logout.ParseResponse(ctx, toIDP(t, partial), sp2.config.EntityID(), toSP2.ID)
	if !errors.Is(err, idpslo.ErrPartialLogout) || resp == nil {
		t.Fatalf("got %v, %v", resp, err)
	}
	var bad saml.ErrBadStatus
	if errors.As(err, &bad) {
		t.Errorf("partial logout matches saml.ErrBadStatus: %v", err)
	}
	if s := resp.Status.StatusCode.StatusCode; s == nil || s.Value != saml.StatusPartialLogout {
		t.Fatalf("status %+v", resp.Status)
	}
}

func TestUnsignedRequestRefused(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t, worldOptions{})
	_, a1 := w.login(t, 0, "s1")
	out, err := w.sps[0].slo.Request(ctx, a1.NameID, "")
	if err != nil {
		t.Fatal(err)
	}
	// The same request without its signature.
	u := out.RedirectURL()
	q := u.Query()
	q.Del("Signature")
	q.Del("SigAlg")
	u.RawQuery = q.Encode()
	if _, err := w.logout.ParseRequest(ctx, httptest.NewRequest(http.MethodGet, u.String(), http.NoBody)); err == nil {
		t.Fatal("an unsigned LogoutRequest was accepted")
	}
}

func TestEncryptedNameID(t *testing.T) {
	ctx := context.Background()
	idpKey, idpCert := keyPair(t, 0)
	sp1Key, sp1Cert := keyPair(t, 1)
	sp2Key, sp2Cert := keyPair(t, 2)
	w := newWorld(t, worldOptions{
		idp: []idpslo.EndpointOption{idpslo.EncryptNameID, idpslo.WithDecryptionKey(idpKey, idpCert)},
		sp:  [2][]slo.EndpointOption{{slo.EncryptNameID}},
		spConfig: [2][]samlsp.Option{
			{samlsp.WithEncryptionKey(sp1Key, sp1Cert)},
			{samlsp.WithEncryptionKey(sp2Key, sp2Cert)},
		},
	})
	var hasEncryptionKey bool
	for _, k := range w.idp.Metadata().IDPSSODescriptors[0].KeyDescriptors {
		hasEncryptionKey = hasEncryptionKey || k.Use == "encryption"
	}
	if !hasEncryptionKey {
		t.Fatal("the IdP metadata publishes no encryption key")
	}

	p1, a1 := w.login(t, 0, "s1")
	p2, _ := w.login(t, 1, "s2")

	// SP 1 encrypts its NameID to the IdP.
	out, err := w.sps[0].slo.Request(ctx, a1.NameID, "", samlsp.WithBinding(saml.HTTPPostBinding))
	if err != nil {
		t.Fatal(err)
	}
	if fields := formOf(t, out); strings.Contains(fields.Get("SAMLRequest"), "alice") {
		t.Fatal("not encrypted")
	}
	req, err := w.logout.ParseRequest(ctx, toIDP(t, out))
	if err != nil {
		t.Fatal(err)
	}
	if !req.Matches(p1) {
		t.Fatalf("decrypted NameID %+v does not match %+v", req.NameID, p1.NameID)
	}

	// The IdP encrypts its NameID to SP 2.
	toSP2, err := w.logout.Request(ctx, p2, "", idpslo.WithBinding(saml.HTTPPostBinding))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(toSP2.FormValues()["SAMLRequest"], "alice") {
		t.Fatal("not encrypted")
	}
	sp2req, err := w.sps[1].slo.ParseRequest(ctx, deliver(t, toSP2))
	if err != nil {
		t.Fatal(err)
	}
	if sp2req.NameID.Value != "alice" {
		t.Fatalf("SP 2 got %+v", sp2req.NameID)
	}
}

// TestBackChannel logs out with the SOAP binding, both ways, over TLS.
func TestBackChannel(t *testing.T) {
	ctx := context.Background()
	var w *world
	sp2Got := make(chan *saml.LogoutRequest, 1)
	var sp2Partial atomic.Bool
	idpServer := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		req, err := w.logout.ParseRequest(r.Context(), r)
		if err != nil {
			idpslo.WriteRequestError(rw, r)
			return
		}
		msg, err := w.logout.Response(r.Context(), req)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		msg.Write(rw)
	}))
	defer idpServer.Close()
	sp2Server := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		s := w.sps[1].slo
		req, err := s.ParseRequest(r.Context(), r)
		if err != nil {
			slo.WriteRequestError(rw, r)
			return
		}
		sp2Got <- req.Raw
		var opts []samlsp.MessageOption
		if sp2Partial.Load() {
			opts = append(opts, slo.WithStatus(partialStatus))
		}
		msg, err := s.Response(r.Context(), req, opts...)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		msg.Write(rw)
	}))
	defer sp2Server.Close()

	w = newWorld(t, worldOptions{
		idp:    []idpslo.EndpointOption{idpslo.BackChannel, idpslo.WithHTTPClient(sp2Server.Client())},
		idpSLO: idpServer.URL + "/saml/slo",
		sp:     [2][]slo.EndpointOption{{slo.BackChannel}, {slo.BackChannel}},
		spConfig: [2][]samlsp.Option{
			{samlsp.WithHTTPClient(idpServer.Client())},
		},
		spBase: [2]string{"", sp2Server.URL},
	})
	soap := w.idp.Metadata().IDPSSODescriptors[0].SingleLogoutServices
	if len(soap) != 3 || soap[2].Binding != saml.SOAPBinding {
		t.Fatalf("SingleLogoutServices = %+v", soap)
	}
	_, a1 := w.login(t, 0, "s1")
	p2, _ := w.login(t, 1, "s1")

	// SP 1 asks the IdP directly.
	resp, err := w.sps[0].slo.SendRequest(ctx, a1.NameID)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status.StatusCode.Value != saml.StatusSuccess {
		t.Fatalf("status %+v", resp.Status)
	}

	// The IdP logs the user out of SP 2 directly.
	deadline := time.Now().Add(time.Minute).UTC().Truncate(time.Millisecond)
	resp, err = w.logout.SendRequest(ctx, p2, idpslo.WithReason(saml.LogoutReasonAdmin), idpslo.WithNotOnOrAfter(deadline))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status.StatusCode.Value != saml.StatusSuccess {
		t.Fatalf("status %+v", resp.Status)
	}
	if got := <-sp2Got; got.Reason != saml.LogoutReasonAdmin || got.NotOnOrAfter == nil || !got.NotOnOrAfter.Equal(deadline) {
		t.Fatalf("SP 2 got %+v", got)
	}

	// SP 2 ends the user's sessions only in part.
	sp2Partial.Store(true)
	resp, err = w.logout.SendRequest(ctx, p2)
	if !errors.Is(err, idpslo.ErrPartialLogout) || resp == nil {
		t.Fatalf("partial: got %v, %v", resp, err)
	}
	<-sp2Got
}

func TestSendRequestNeedsBackChannel(t *testing.T) {
	w := newWorld(t, worldOptions{})
	p2, _ := w.login(t, 1, "s1")
	if _, err := w.logout.SendRequest(context.Background(), p2); err == nil {
		t.Fatal("no error")
	}
}

func TestNoEndpoint(t *testing.T) {
	ctx := context.Background()
	key, cert := keyPair(t, 0)
	spKey, spCert := keyPair(t, 1)
	plain, err := samlsp.New("https://plain.example.com/saml/metadata", nil, samlsp.WithSigningKey(spKey, spCert))
	if err != nil {
		t.Fatal(err)
	}
	idp, err := samlidp.New(idpEntityID, samlidp.StaticServiceProviders(plain.Metadata(ctx)),
		samlidp.WithSigningKey(key, cert), idpslo.Endpoint("https://idp.example.com/saml/slo", idpslo.BackChannel))
	if err != nil {
		t.Fatal(err)
	}
	logout, err := idpslo.New(idp)
	if err != nil {
		t.Fatal(err)
	}
	p := saml.SessionParticipant{ServiceProviderID: plain.EntityID(), NameID: saml.NameID{Value: "alice"}}
	if _, err := logout.Request(ctx, p, ""); !errors.Is(err, idpslo.ErrNoEndpoint) {
		t.Fatalf("got %v", err)
	}
	if _, err := logout.SendRequest(ctx, p); !errors.Is(err, idpslo.ErrNoEndpoint) {
		t.Fatalf("SendRequest: got %v", err)
	}
	p.ServiceProviderID = "https://unknown.example.com"
	if _, err := logout.Request(ctx, p, ""); !errors.Is(err, samlidp.ErrUnknownServiceProvider) {
		t.Fatalf("got %v", err)
	}
}

func TestConfig(t *testing.T) {
	key, cert := keyPair(t, 0)
	_, otherCert := keyPair(t, 1)
	sps := samlidp.StaticServiceProviders()
	for name, opt := range map[string]samlidp.Option{
		"relative URL":    idpslo.Endpoint("/slo"),
		"wrong cert":      idpslo.Endpoint("https://idp.example.com/slo", idpslo.WithDecryptionKey(key, otherCert)),
		"unparseable URL": idpslo.Endpoint("https://idp.example.com/%zz"),
	} {
		if _, err := samlidp.New(idpEntityID, sps, samlidp.WithSigningKey(key, cert), opt); err == nil {
			t.Errorf("%s: no error", name)
		}
	}

	c, err := samlidp.New(idpEntityID, sps, samlidp.WithSigningKey(key, cert))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := idpslo.New(c); err == nil {
		t.Error("New without Endpoint: no error")
	}

	c, err = samlidp.New(idpEntityID, sps, samlidp.WithSigningKey(key, cert), idpslo.Endpoint("https://idp.example.com/saml/slo"))
	if err != nil {
		t.Fatal(err)
	}
	logout, err := idpslo.New(c)
	if err != nil {
		t.Fatal(err)
	}
	if logout.URL() != "https://idp.example.com/saml/slo" || logout.Path() != "/saml/slo" {
		t.Errorf("got %q %q", logout.URL(), logout.Path())
	}
	d := c.Metadata().IDPSSODescriptors[0]
	if len(d.SingleLogoutServices) != 2 || d.SingleLogoutServices[0].Binding != saml.HTTPRedirectBinding || d.SingleLogoutServices[1].Binding != saml.HTTPPostBinding {
		t.Errorf("SingleLogoutServices = %+v", d.SingleLogoutServices)
	}
	for _, k := range d.KeyDescriptors {
		if k.Use == "encryption" {
			t.Error("an encryption key is published without WithDecryptionKey")
		}
	}
}

func TestRequestRelayStateTooLong(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t, worldOptions{})
	p2, _ := w.login(t, 1, "s1")
	if _, err := w.logout.Request(ctx, p2, strings.Repeat("r", saml.MaxRelayStateLength)); err != nil {
		t.Fatal(err)
	}
	if _, err := w.logout.Request(ctx, p2, strings.Repeat("r", saml.MaxRelayStateLength+1)); !errors.Is(err, saml.ErrRelayStateTooLong) {
		t.Fatalf("got %v", err)
	}
}

// TestResponseReplay checks that a LogoutResponse is accepted only once,
// even while the request it answers is still pending.
func TestResponseReplay(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t, worldOptions{})
	p2, _ := w.login(t, 1, "s1")
	toSP2, err := w.logout.Request(ctx, p2, "")
	if err != nil {
		t.Fatal(err)
	}
	sp2 := w.sps[1]
	sp2req, err := sp2.slo.ParseRequest(ctx, deliver(t, toSP2))
	if err != nil {
		t.Fatal(err)
	}
	answer, err := sp2.slo.Response(ctx, sp2req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.logout.ParseResponse(ctx, toIDP(t, answer), sp2.config.EntityID(), toSP2.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := w.logout.ParseResponse(ctx, toIDP(t, answer), sp2.config.EntityID(), toSP2.ID); !errors.Is(err, saml.ErrAssertionReplayed) {
		t.Fatalf("replayed: got %v", err)
	}
}
