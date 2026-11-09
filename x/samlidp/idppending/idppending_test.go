package idppending_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	dsig "github.com/russellhaering/goxmldsig"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlidp"
	"github.com/crewjam/saml/x/samlidp/idppending"
)

const (
	idpEntityID = "https://idp.example.com/saml/metadata"
	spEntityID  = "https://sp.example.com/saml/metadata"
	acsURL      = "https://sp.example.com/saml/acs"
)

var (
	testKey  = []byte("0123456789abcdef0123456789abcdef")
	otherKey = []byte("fedcba9876543210fedcba9876543210")
	t0       = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
)

func spMetadata() *saml.EntityDescriptor {
	return &saml.EntityDescriptor{
		EntityID: spEntityID,
		SPSSODescriptors: []saml.SPSSODescriptor{{
			SSODescriptor: saml.SSODescriptor{RoleDescriptor: saml.RoleDescriptor{
				ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
			}},
			AssertionConsumerServices: []saml.IndexedEndpoint{{Binding: saml.HTTPPostBinding, Location: acsURL, Index: 1}},
		}},
	}
}

// keyPair returns a signing key and its certificate, valid at now.
func keyPair(t *testing.T, now time.Time) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "idp"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

// newConfig returns a samlidp.Config whose clock reads now.
func newConfig(t *testing.T, now time.Time) *samlidp.Config {
	t.Helper()
	key, cert := keyPair(t, now)
	config, err := samlidp.New(idpEntityID, samlidp.StaticServiceProviders(spMetadata()),
		samlidp.WithSigningKey(key, cert), samlidp.WithClock(dsig.NewFakeClockAt(now)))
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func equalJSON(t *testing.T, a, b any) bool {
	t.Helper()
	ja, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	jb, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return string(ja) == string(jb)
}

func newTracker(t *testing.T, config *samlidp.Config, opts ...idppending.Option) *idppending.Tracker {
	t.Helper()
	tr, err := idppending.New(config, testKey, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

// browser is a cookie jar for one browser.
type browser struct{ cookies map[string]string }

func newBrowser() *browser { return &browser{cookies: map[string]string{}} }

// request returns a request to the IdP that carries the browser's cookies.
func (b *browser) request() *http.Request {
	r := httptest.NewRequest(http.MethodPost, "https://idp.example.com/login", nil)
	for name, value := range b.cookies {
		r.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	return r
}

// keep stores the cookies that w set, and removes those it cleared.
func (b *browser) keep(w *httptest.ResponseRecorder) {
	for _, c := range w.Result().Cookies() {
		if c.MaxAge < 0 {
			delete(b.cookies, c.Name)
		} else {
			b.cookies[c.Name] = c.Value
		}
	}
}

func (b *browser) remember(t *testing.T, tr *idppending.Tracker, req *samlidp.AuthnRequest) string {
	t.Helper()
	w := httptest.NewRecorder()
	handle, err := tr.Remember(w, b.request(), req)
	if err != nil {
		t.Fatal(err)
	}
	b.keep(w)
	return handle
}

func (b *browser) take(tr *idppending.Tracker, handle string) (*samlidp.AuthnRequest, error) {
	w := httptest.NewRecorder()
	req, err := tr.Take(w, b.request(), handle)
	b.keep(w)
	return req, err
}

func simpleRequest(id, relayState string) *samlidp.AuthnRequest {
	return &samlidp.AuthnRequest{
		ID:              id,
		ServiceProvider: spEntityID,
		IssueInstant:    t0.Add(-time.Second),
		RelayState:      relayState,
		ACSURL:          acsURL,
		ACSBinding:      saml.HTTPPostBinding,
		AllowCreate:     true,
	}
}

func TestRoundTrip(t *testing.T) {
	config := newConfig(t, t0)
	tr := newTracker(t, config)
	proxy := 2
	req := &samlidp.AuthnRequest{
		ID:                             "id-1234567890abcdef",
		ServiceProvider:                spEntityID,
		IssueInstant:                   t0.Add(-1234567891 * time.Nanosecond),
		RelayState:                     "~state with a tilde",
		ACSURL:                         acsURL,
		ACSBinding:                     saml.HTTPPostSimpleSignBinding,
		ProviderName:                   "Example SP",
		Consent:                        "urn:oasis:names:tc:SAML:2.0:consent:obtained",
		AttributeConsumingServiceIndex: "3",
		Scoping: &saml.Scoping{
			ProxyCount:   &proxy,
			IDPList:      &saml.IDPList{IDPEntries: []saml.IDPEntry{{ProviderID: "https://other.example.com", Name: "Other", Loc: "https://other.example.com/sso"}}, GetComplete: "https://x.example.com/list"},
			RequesterIDs: []string{"https://requester.example.com"},
		},
		ForceAuthn:             true,
		IsPassive:              true,
		NameIDFormat:           saml.PersistentNameIDFormat,
		SPNameQualifier:        "https://affiliation.example.com",
		AllowCreate:            true,
		AuthnContextComparison: saml.AuthnContextComparisonMinimum,
		AuthnContextClasses:    []saml.AuthnContextClass{saml.AuthnContextPasswordProtectedTransport, "urn:example:mfa"},
		AuthnContextDecls:      []string{"urn:example:decl"},
		Subject:                &saml.NameID{Format: string(saml.EmailAddressNameIDFormat), Value: "alice@example.com", NameQualifier: "q", SPNameQualifier: "sq", SPProvidedID: "p"},
		Signed:                 true,
		Extensions:             [][]byte{[]byte(`<x:E xmlns:x="urn:example">é</x:E>`)},
	}
	b := newBrowser()
	handle := b.remember(t, tr, req)

	peeked, err := tr.Peek(b.request(), handle)
	if err != nil {
		t.Fatalf("Peek: %v", err)
	}
	got, err := b.take(tr, handle)
	if err != nil {
		t.Fatalf("Take: %v", err)
	}
	for _, r := range []*samlidp.AuthnRequest{peeked, got} {
		if !r.IssueInstant.Equal(req.IssueInstant) {
			t.Errorf("IssueInstant = %v, want %v", r.IssueInstant, req.IssueInstant)
		}
		r.IssueInstant = req.IssueInstant
		if !equalJSON(t, r, req) {
			t.Errorf("round trip:\n got %+v\nwant %+v", r, req)
		}
	}
}

func TestRoundTripEmptyFields(t *testing.T) {
	tr := newTracker(t, newConfig(t, t0))
	req := &samlidp.AuthnRequest{ServiceProvider: spEntityID, ACSURL: "http://sp.example.com/acs", ACSBinding: "urn:example:binding"}
	b := newBrowser()
	got, err := b.take(tr, b.remember(t, tr, req))
	if err != nil {
		t.Fatal(err)
	}
	if !equalJSON(t, got, req) || !got.IssueInstant.IsZero() || got.Scoping != nil || got.Subject != nil {
		t.Errorf("round trip:\n got %+v\nwant %+v", got, req)
	}
}

// TestAnswer answers a request taken from the cookie, as an application
// would.
func TestAnswer(t *testing.T) {
	config := newConfig(t, t0)
	tr := newTracker(t, config)
	req, err := config.IDPInitiated(t.Context(), spEntityID, "relay")
	if err != nil {
		t.Fatal(err)
	}
	b := newBrowser()
	got, err := b.take(tr, b.remember(t, tr, req))
	if err != nil {
		t.Fatal(err)
	}
	msg, err := config.Response(t.Context(), got, samlidp.Subject{NameID: "alice", AuthnInstant: t0})
	if err != nil {
		t.Fatal(err)
	}
	if msg.Destination != acsURL || msg.RelayState != "relay" {
		t.Errorf("Response to %s with RelayState %q", msg.Destination, msg.RelayState)
	}
}

func TestSecondTakeRefused(t *testing.T) {
	tr := newTracker(t, newConfig(t, t0))
	b := newBrowser()
	handle := b.remember(t, tr, simpleRequest("id-1", "s"))
	if _, err := b.take(tr, handle); err != nil {
		t.Fatal(err)
	}
	if len(b.cookies) != 0 {
		t.Errorf("Take left cookies %v", b.cookies)
	}
	if _, err := b.take(tr, handle); !errors.Is(err, idppending.ErrNotFound) {
		t.Errorf("second Take: %v, want ErrNotFound", err)
	}
	if _, err := tr.Peek(b.request(), handle); !errors.Is(err, idppending.ErrNotFound) {
		t.Errorf("Peek after Take: %v, want ErrNotFound", err)
	}
}

// TestReplayedCookie shows the limit of Take alone, and RecordTaken.
func TestReplayedCookie(t *testing.T) {
	t.Run("without RecordTaken", func(t *testing.T) {
		tr := newTracker(t, newConfig(t, t0))
		b := newBrowser()
		handle := b.remember(t, tr, simpleRequest("id-1", "s"))
		copied := *b.request()
		if _, err := tr.Take(httptest.NewRecorder(), &copied, handle); err != nil {
			t.Fatal(err)
		}
		// A browser that ignores the clearing can take it again.
		if _, err := tr.Take(httptest.NewRecorder(), &copied, handle); err != nil {
			t.Errorf("Take of a kept cookie: %v; the limitation is documented, so this is expected to succeed", err)
		}
	})
	for _, tc := range []struct {
		name string
		req  *samlidp.AuthnRequest
	}{
		{"SP-initiated", simpleRequest("id-1", "s")},
		{"IdP-initiated", simpleRequest("", "s")},
		{"signed", func() *samlidp.AuthnRequest { r := simpleRequest("id-signed", "s"); r.Signed = true; return r }()},
	} {
		t.Run("RecordTaken "+tc.name, func(t *testing.T) {
			config := newConfig(t, t0)
			if tc.req.Signed {
				// ParseAuthnRequest recorded the signed request under its
				// bare ID: Take's record must not collide with it.
				if err := config.Consume(t.Context(), tc.req.ServiceProvider, tc.req.ID, t0.Add(time.Hour)); err != nil {
					t.Fatal(err)
				}
			}
			tr := newTracker(t, config, idppending.RecordTaken)
			b := newBrowser()
			handle := b.remember(t, tr, tc.req)
			kept := b.request()
			if _, err := b.take(tr, handle); err != nil {
				t.Fatal(err)
			}
			_, err := tr.Take(httptest.NewRecorder(), kept, handle)
			if !errors.Is(err, idppending.ErrTaken) || !errors.Is(err, saml.ErrAssertionReplayed) {
				t.Errorf("Take of a kept cookie: %v, want ErrTaken", err)
			}
		})
	}
	t.Run("RecordTaken same request remembered twice", func(t *testing.T) {
		tr := newTracker(t, newConfig(t, t0), idppending.RecordTaken)
		b := newBrowser()
		h1 := b.remember(t, tr, simpleRequest("id-1", "s"))
		h2 := b.remember(t, tr, simpleRequest("id-1", "s"))
		if _, err := b.take(tr, h1); err != nil {
			t.Fatal(err)
		}
		if _, err := b.take(tr, h2); !errors.Is(err, idppending.ErrTaken) {
			t.Errorf("Take of the same request again: %v, want ErrTaken", err)
		}
	})
	t.Run("RecordTaken IdP-initiated logins are separate", func(t *testing.T) {
		tr := newTracker(t, newConfig(t, t0), idppending.RecordTaken)
		b := newBrowser()
		h1 := b.remember(t, tr, simpleRequest("", "s"))
		h2 := b.remember(t, tr, simpleRequest("", "s"))
		if _, err := b.take(tr, h1); err != nil {
			t.Fatal(err)
		}
		if _, err := b.take(tr, h2); err != nil {
			t.Errorf("second IdP-initiated login: %v", err)
		}
	})
}

func TestExpired(t *testing.T) {
	config := newConfig(t, t0)
	tr := newTracker(t, config, idppending.WithMaxAge(time.Minute))
	b := newBrowser()
	handle := b.remember(t, tr, simpleRequest("id-1", "s"))

	// The request's own IssueInstant does not matter: it is long past.
	if _, err := tr.Peek(b.request(), handle); err != nil {
		t.Fatalf("Peek before expiry: %v", err)
	}
	later, err := idppending.New(newConfig(t, t0.Add(time.Minute)), testKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := later.Peek(b.request(), handle); !errors.Is(err, idppending.ErrExpired) {
		t.Errorf("Peek after expiry: %v, want ErrExpired", err)
	}
	if _, err := b.take(later, handle); !errors.Is(err, idppending.ErrExpired) {
		t.Errorf("Take after expiry: %v, want ErrExpired", err)
	}
	if len(b.cookies) != 0 {
		t.Errorf("Take left the expired cookie: %v", b.cookies)
	}
}

func TestDefaultMaxAge(t *testing.T) {
	tr := newTracker(t, newConfig(t, t0))
	w := httptest.NewRecorder()
	if _, err := tr.Remember(w, nil, simpleRequest("id-1", "s")); err != nil {
		t.Fatal(err)
	}
	c := w.Result().Cookies()[0]
	if c.MaxAge != int(idppending.DefaultMaxAge/time.Second) || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.Path != "/" {
		t.Errorf("cookie %+v", c)
	}
	if !strings.HasPrefix(c.Name, idppending.DefaultCookiePrefix) {
		t.Errorf("cookie name %q", c.Name)
	}
}

func TestTamper(t *testing.T) {
	tr := newTracker(t, newConfig(t, t0))
	b := newBrowser()
	handle := b.remember(t, tr, simpleRequest("id-1", "s"))
	var name string
	for n := range b.cookies {
		name = n
	}
	value := b.cookies[name]
	for i := range value {
		c := value[i] ^ 1
		if c == '-' || c == '_' || ('0' <= c && c <= '9') || ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') {
			b.cookies[name] = value[:i] + string(c) + value[i+1:]
		} else {
			b.cookies[name] = value[:i] + "A" + value[i+1:]
			if b.cookies[name] == value {
				continue
			}
		}
		if _, err := tr.Peek(b.request(), handle); !errors.Is(err, idppending.ErrInvalid) {
			t.Fatalf("Peek of a cookie changed at %d: %v, want ErrInvalid", i, err)
		}
	}
	b.cookies[name] = value[:len(value)-4]
	if _, err := b.take(tr, handle); !errors.Is(err, idppending.ErrInvalid) {
		t.Errorf("Take of a truncated cookie: %v, want ErrInvalid", err)
	}
	if len(b.cookies) != 0 {
		t.Errorf("Take left the invalid cookie: %v", b.cookies)
	}

	// A cookie made with another key is not valid either.
	other, err := idppending.New(newConfig(t, t0), otherKey)
	if err != nil {
		t.Fatal(err)
	}
	handle = b.remember(t, other, simpleRequest("id-1", "s"))
	if _, err := tr.Peek(b.request(), handle); !errors.Is(err, idppending.ErrInvalid) {
		t.Errorf("Peek of another key's cookie: %v, want ErrInvalid", err)
	}
}

func TestMalformedHandle(t *testing.T) {
	tr := newTracker(t, newConfig(t, t0))
	b := newBrowser()
	handle := b.remember(t, tr, simpleRequest("id-1", "s"))
	slot, token, _ := strings.Cut(handle, ".")
	for _, h := range []string{"", "x", slot, slot + ".", "99." + token, "-1." + token, "0" + slot + "." + token, slot + "." + token + "A", "+" + slot + "." + token} {
		if _, err := tr.Peek(b.request(), h); !errors.Is(err, idppending.ErrNotFound) {
			t.Errorf("Peek(%q): %v, want ErrNotFound", h, err)
		}
	}
}

// TestSwapSlots moves a cookie to another slot, and swaps the values of two
// slots: neither is accepted.
func TestSwapSlots(t *testing.T) {
	tr := newTracker(t, newConfig(t, t0))
	b := newBrowser()
	h1 := b.remember(t, tr, simpleRequest("id-1", "one"))
	h2 := b.remember(t, tr, simpleRequest("id-2", "two"))
	n1 := idppending.DefaultCookiePrefix + strings.Split(h1, ".")[0]
	n2 := idppending.DefaultCookiePrefix + strings.Split(h2, ".")[0]
	if n1 == n2 {
		t.Fatalf("both requests in %s", n1)
	}
	b.cookies[n1], b.cookies[n2] = b.cookies[n2], b.cookies[n1]
	for _, h := range []string{h1, h2} {
		if _, err := tr.Peek(b.request(), h); !errors.Is(err, idppending.ErrInvalid) {
			t.Errorf("Peek(%s) of swapped cookies: %v, want ErrInvalid", h, err)
		}
	}

	// The handle of one request with the slot of the other.
	b.cookies[n1], b.cookies[n2] = b.cookies[n2], b.cookies[n1]
	_, token1, _ := strings.Cut(h1, ".")
	slot2, _, _ := strings.Cut(h2, ".")
	if _, err := tr.Peek(b.request(), slot2+"."+token1); !errors.Is(err, idppending.ErrNotFound) {
		t.Errorf("Peek with another slot's token: %v, want ErrNotFound", err)
	}
	// Planting another browser's cookie, with its own handle, is the
	// cookie tossing that __Host- prevents; planting it under the user's
	// handle fails.
	other := newBrowser()
	ho := other.remember(t, tr, simpleRequest("id-attacker", "attacker"))
	no := idppending.DefaultCookiePrefix + strings.Split(ho, ".")[0]
	b.cookies[no] = other.cookies[no]
	for _, h := range []string{h1, h2} {
		if got, err := tr.Peek(b.request(), h); err == nil && got.ID == "id-attacker" {
			t.Errorf("Peek(%s) returned the planted request", h)
		}
	}
}

// TestMultipleTabs remembers a request in each of several tabs, and
// takes them in another order.
func TestMultipleTabs(t *testing.T) {
	tr := newTracker(t, newConfig(t, t0))
	b := newBrowser()
	handles := make([]string, 0, idppending.DefaultSlots)
	for i := range idppending.DefaultSlots {
		handles = append(handles, b.remember(t, tr, simpleRequest("id-"+strconv.Itoa(i), "s")))
	}
	if len(b.cookies) != idppending.DefaultSlots {
		t.Fatalf("%d cookies, want %d: Remember did not pick free slots", len(b.cookies), idppending.DefaultSlots)
	}
	for _, i := range []int{2, 0, 3, 1} {
		got, err := b.take(tr, handles[i])
		if err != nil {
			t.Fatalf("Take of tab %d: %v", i, err)
		}
		if want := "id-" + strconv.Itoa(i); got.ID != want {
			t.Errorf("tab %d took %s, want %s", i, got.ID, want)
		}
	}

	// With every slot in use, a new request replaces one, whose handle
	// then fails rather than taking the new request.
	handles = handles[:0]
	for i := range idppending.DefaultSlots {
		handles = append(handles, b.remember(t, tr, simpleRequest("id-"+strconv.Itoa(i), "s")))
	}
	later := newTracker(t, newConfig(t, t0.Add(time.Second)))
	extra := b.remember(t, later, simpleRequest("id-extra", "s"))
	replaced := 0
	for _, h := range handles {
		if _, err := tr.Peek(b.request(), h); errors.Is(err, idppending.ErrNotFound) {
			replaced++
		} else if err != nil {
			t.Errorf("Peek(%s): %v", h, err)
		}
	}
	if replaced != 1 {
		t.Errorf("%d requests replaced, want 1", replaced)
	}
	if got, err := b.take(tr, extra); err != nil || got.ID != "id-extra" {
		t.Errorf("Take of the new request: %v, %v", got, err)
	}
}

// TestOldestReplaced checks that with every slot in use, the request that
// expires first is replaced.
func TestOldestReplaced(t *testing.T) {
	b := newBrowser()
	handles := make([]string, 0, idppending.DefaultSlots)
	for i := range idppending.DefaultSlots {
		tr := newTracker(t, newConfig(t, t0.Add(time.Duration(i)*time.Second)))
		handles = append(handles, b.remember(t, tr, simpleRequest("id", "s")))
	}
	tr := newTracker(t, newConfig(t, t0.Add(time.Minute)))
	b.remember(t, tr, simpleRequest("id-new", "s"))
	if _, err := tr.Peek(b.request(), handles[0]); !errors.Is(err, idppending.ErrNotFound) {
		t.Errorf("Peek of the oldest: %v, want ErrNotFound", err)
	}
	for _, h := range handles[1:] {
		if _, err := tr.Peek(b.request(), h); err != nil {
			t.Errorf("Peek(%s): %v", h, err)
		}
	}
}

func TestCookieSize(t *testing.T) {
	tr := newTracker(t, newConfig(t, t0))
	limit := idppending.DefaultMaxCookiesSize / idppending.DefaultSlots

	// A typical request.
	w := httptest.NewRecorder()
	if _, err := tr.Remember(w, nil, simpleRequest("id-"+strings.Repeat("0", 40), "26CHARACTERRELAYSTATEABCDE")); err != nil {
		t.Fatal(err)
	}
	c := w.Result().Cookies()[0]
	size := len(c.Name) + 1 + len(c.Value) + 2
	t.Logf("a typical slot cookie takes %d bytes", size)
	if size > 420 {
		t.Errorf("a typical slot cookie takes %d bytes", size)
	}

	// The 80-byte RelayState of saml-bindings §3.4.3 fits.
	if _, err := tr.Remember(httptest.NewRecorder(), nil, simpleRequest("id-1", strings.Repeat("r", 80))); err != nil {
		t.Errorf("80-byte RelayState: %v", err)
	}
	// A larger one fits up to the limit, and no further.
	var largest int
	for n := 80; n < 4096; n++ {
		w := httptest.NewRecorder()
		if _, err := tr.Remember(w, nil, simpleRequest("id-1", strings.Repeat("r", n))); err != nil {
			if !strings.Contains(err.Error(), "WithMaxCookiesSize") {
				t.Fatal(err)
			}
			if len(w.Result().Cookies()) != 0 {
				t.Error("Remember set a cookie it refused")
			}
			break
		}
		c := w.Result().Cookies()[0]
		if size := len(c.Name) + 1 + len(c.Value) + 2; size > limit {
			t.Fatalf("a %d-byte cookie was set, more than %d", size, limit)
		}
		largest = n
	}
	t.Logf("the largest RelayState that fits is %d bytes", largest)
	if largest < 800 || largest >= 4095 {
		t.Errorf("the largest RelayState that fits is %d bytes", largest)
	}

	// With a larger budget, more fits.
	roomy := newTracker(t, newConfig(t, t0), idppending.WithMaxCookiesSize(16<<10))
	if _, err := roomy.Remember(httptest.NewRecorder(), nil, simpleRequest("id-1", strings.Repeat("r", 1500))); err != nil {
		t.Errorf("WithMaxCookiesSize: %v", err)
	}
	// But never beyond what browsers keep.
	if _, err := roomy.Remember(httptest.NewRecorder(), nil, simpleRequest("id-1", strings.Repeat("r", 3800))); err == nil {
		t.Error("Remember accepted a cookie larger than browsers keep")
	}
}

func TestNew(t *testing.T) {
	config := newConfig(t, t0)
	httpConfig, err := samlidp.New("http://idp.example.com/metadata", samlidp.StaticServiceProviders(),
		samlidp.WithSigningKey(keyPair(t, t0)))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		config *samlidp.Config
		key    []byte
		opts   []idppending.Option
		ok     bool
	}{
		{"default", config, testKey, nil, true},
		{"nil config", nil, testKey, nil, false},
		{"short key", config, testKey[:31], nil, false},
		{"zero max age", config, testKey, []idppending.Option{idppending.WithMaxAge(0)}, false},
		{"no slots", config, testKey, []idppending.Option{idppending.WithSlots(0)}, false},
		{"too many slots", config, testKey, []idppending.Option{idppending.WithSlots(idppending.MaxSlots + 1)}, false},
		{"too little room", config, testKey, []idppending.Option{idppending.WithMaxCookiesSize(1000)}, false},
		{"bad prefix", config, testKey, []idppending.Option{idppending.WithCookiePrefix("a=b")}, false},
		{"relative path", config, testKey, []idppending.Option{idppending.WithPath("login")}, false},
		{"__Host-", config, testKey, []idppending.Option{idppending.WithCookiePrefix("__Host-p")}, true},
		{"__host- lower case with path", config, testKey, []idppending.Option{idppending.WithCookiePrefix("__host-p"), idppending.WithPath("/login")}, false},
		{"__Host- with domain", config, testKey, []idppending.Option{idppending.WithCookiePrefix("__Host-p"), idppending.WithDomain("example.com")}, false},
		{"__Host- over http", httpConfig, testKey, []idppending.Option{idppending.WithCookiePrefix("__Host-p")}, false},
		{"__Secure- over http", httpConfig, testKey, []idppending.Option{idppending.WithCookiePrefix("__Secure-p")}, false},
		{"__Secure- with path", config, testKey, []idppending.Option{idppending.WithCookiePrefix("__Secure-p"), idppending.WithPath("/login")}, true},
		{"http", httpConfig, testKey, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := idppending.New(tc.config, tc.key, tc.opts...)
			if (err == nil) != tc.ok {
				t.Errorf("New: %v", err)
			}
		})
	}

	// Over http, the cookie is not Secure.
	tr := newTracker(t, httpConfig)
	w := httptest.NewRecorder()
	if _, err := tr.Remember(w, nil, simpleRequest("id-1", "s")); err != nil {
		t.Fatal(err)
	}
	if c := w.Result().Cookies()[0]; c.Secure {
		t.Errorf("cookie over http is Secure: %+v", c)
	}
}

func TestDeriveKey(t *testing.T) {
	k1, err := idppending.DeriveKey(testKey, "a")
	if err != nil {
		t.Fatal(err)
	}
	k2, _ := idppending.DeriveKey(testKey, "b")
	if len(k1) < idppending.MinKeyLength || string(k1) == string(k2) || string(k1) == string(testKey) {
		t.Error("DeriveKey does not separate labels")
	}
	if _, err := idppending.DeriveKey(testKey[:31], "a"); err == nil {
		t.Error("DeriveKey accepted a short secret")
	}
	if _, err := idppending.DeriveKey(testKey, ""); err == nil {
		t.Error("DeriveKey accepted an empty label")
	}
}

func TestRememberErrors(t *testing.T) {
	tr := newTracker(t, newConfig(t, t0))
	for _, req := range []*samlidp.AuthnRequest{
		nil,
		{ID: "id-1"},
		{ServiceProvider: spEntityID, Extensions: [][]byte{{0xff}}},
	} {
		w := httptest.NewRecorder()
		if _, err := tr.Remember(w, nil, req); err == nil || len(w.Result().Cookies()) != 0 {
			t.Errorf("Remember(%+v): %v", req, err)
		}
	}
}
