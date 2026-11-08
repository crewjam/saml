package samlidp

import (
	"crypto/rsa"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
	"gotest.tools/v3/golden"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/logger"
)

var errCovStore = errors.New("cov: store failure")

// covStore wraps a MemoryStore and allows individual operations to be made to
// fail. Each hook receives the key (or prefix) and returns the error to report,
// or nil to fall through to the MemoryStore.
type covStore struct {
	MemoryStore
	getErr    func(key string) error
	putErr    func(key string) error
	deleteErr func(key string) error
	listErr   func(prefix string) error
}

func (s *covStore) Get(key string, value interface{}) error {
	if s.getErr != nil {
		if err := s.getErr(key); err != nil {
			return err
		}
	}
	return s.MemoryStore.Get(key, value)
}

func (s *covStore) Put(key string, value interface{}) error {
	if s.putErr != nil {
		if err := s.putErr(key); err != nil {
			return err
		}
	}
	return s.MemoryStore.Put(key, value)
}

func (s *covStore) Delete(key string) error {
	if s.deleteErr != nil {
		if err := s.deleteErr(key); err != nil {
			return err
		}
	}
	return s.MemoryStore.Delete(key)
}

func (s *covStore) List(prefix string) ([]string, error) {
	if s.listErr != nil {
		if err := s.listErr(prefix); err != nil {
			return nil, err
		}
	}
	return s.MemoryStore.List(prefix)
}

// covAlways returns a hook that always fails with errCovStore.
func covAlways(string) error { return errCovStore }

// covFailWriter is an http.ResponseWriter whose body writes always fail.
type covFailWriter struct {
	header http.Header
	code   int
}

func (w *covFailWriter) Header() http.Header {
	if w.header == nil {
		w.header = http.Header{}
	}
	return w.header
}

func (w *covFailWriter) Write([]byte) (int, error) {
	return 0, errors.New("cov: write failure")
}

func (w *covFailWriter) WriteHeader(code int) {
	if w.code == 0 {
		w.code = code
	}
}

// covErrReader is an io.Reader that always fails.
type covErrReader struct{}

func (covErrReader) Read([]byte) (int, error) { return 0, errors.New("cov: read failure") }

// covShortReader returns at most one byte per Read call.
type covShortReader struct{ next byte }

func (r *covShortReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	r.next++
	p[0] = r.next
	return 1, nil
}

// covFixTime pins saml.TimeNow and saml.RandReader for the duration of the test.
func covFixTime(t *testing.T) {
	t.Helper()
	oldTimeNow, oldRand := saml.TimeNow, saml.RandReader
	t.Cleanup(func() {
		saml.TimeNow = oldTimeNow
		saml.RandReader = oldRand
	})
	now := time.Date(2015, 12, 1, 1, 57, 9, 0, time.UTC)
	saml.TimeNow = func() time.Time { return now }
	saml.RandReader = &testRandomReader{}
}

// covNewServer creates a Server backed by store, pinning time/randomness.
func covNewServer(t *testing.T, store Store) *Server {
	t.Helper()
	covFixTime(t)
	s, err := New(Options{
		Certificate: mustParseCertificate(golden.Get(t, "idp_cert.pem")),
		Key:         mustParsePrivateKey(golden.Get(t, "idp_key.pem")).(*rsa.PrivateKey),
		Logger:      logger.DefaultLogger,
		Store:       store,
		URL:         url.URL{Scheme: "https", Host: "idp.example.com", Path: "/"},
	})
	assert.NilError(t, err)
	return s
}

func TestCovNewDefaultsAndTrailingSlash(t *testing.T) {
	covFixTime(t)
	s, err := New(Options{
		Store: &MemoryStore{},
		URL:   url.URL{Scheme: "https", Host: "idp.example.com", Path: "/idp/"},
	})
	assert.NilError(t, err)
	assert.Check(t, s.logger == logger.DefaultLogger)
	assert.Check(t, s.IDP.Logger == logger.DefaultLogger)
	assert.Check(t, is.Equal("https://idp.example.com/idp/metadata", s.IDP.MetadataURL.String()))
	assert.Check(t, is.Equal("https://idp.example.com/idp/sso", s.IDP.SSOURL.String()))
	assert.Check(t, is.Equal("https://idp.example.com/idp/login", s.IDP.LoginURL.String()))
}

func TestCovNewInitializeServicesListError(t *testing.T) {
	covFixTime(t)
	s, err := New(Options{
		Store: &covStore{listErr: covAlways},
		URL:   url.URL{Scheme: "https", Host: "idp.example.com"},
	})
	assert.Check(t, is.ErrorContains(err, "cov: store failure"))
	assert.Check(t, s == nil)
}

func TestCovNewInitializeServicesGetError(t *testing.T) {
	covFixTime(t)
	store := &covStore{}
	assert.NilError(t, store.Put("/services/sp", &Service{Name: "sp"}))
	store.getErr = covAlways
	s, err := New(Options{
		Store: store,
		URL:   url.URL{Scheme: "https", Host: "idp.example.com"},
	})
	assert.Check(t, is.ErrorContains(err, "cov: store failure"))
	assert.Check(t, s == nil)
}

func TestCovNewInitializeServicesLoadsStoredServices(t *testing.T) {
	store := &MemoryStore{}
	assert.NilError(t, store.Put("/services/sp", &Service{
		Name:     "sp",
		Metadata: saml.EntityDescriptor{EntityID: "https://sp.example.com/saml2/metadata"},
	}))
	s := covNewServer(t, store)

	sp, err := s.GetServiceProvider(nil, "https://sp.example.com/saml2/metadata")
	assert.NilError(t, err)
	assert.Check(t, is.Equal("https://sp.example.com/saml2/metadata", sp.EntityID))

	_, err = s.GetServiceProvider(nil, "https://unknown.example.com/")
	assert.Check(t, errors.Is(err, os.ErrNotExist))
}

func TestCovMemoryStorePutMarshalError(t *testing.T) {
	store := &MemoryStore{}
	err := store.Put("/k", make(chan int))
	assert.Check(t, is.ErrorContains(err, "unsupported type"))
	_, err = store.List("/")
	assert.NilError(t, err)
	assert.Check(t, errors.Is(store.Get("/k", new(string)), ErrNotFound))
}

func TestCovMemoryStoreConcurrentAccess(t *testing.T) {
	// List used to read the map without holding the lock, which is a data
	// race with Put/Delete. Run with -race to detect a regression.
	store := &MemoryStore{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			_ = store.Put("/a/x", i)
			_ = store.Delete("/a/x")
		}
	}()
	for i := 0; i < 200; i++ {
		_, err := store.List("/a/")
		assert.NilError(t, err)
	}
	<-done
}

func TestCovRandomBytesPanicsOnReadError(t *testing.T) {
	old := saml.RandReader
	t.Cleanup(func() { saml.RandReader = old })
	saml.RandReader = covErrReader{}

	defer func() {
		r := recover()
		assert.Check(t, r != nil)
		err, ok := r.(error)
		assert.Check(t, ok)
		assert.Check(t, is.ErrorContains(err, "cov: read failure"))
	}()
	randomBytes(8)
	t.Fatal("expected panic")
}

func TestCovRandomBytesFillsBufferOnShortReads(t *testing.T) {
	old := saml.RandReader
	t.Cleanup(func() { saml.RandReader = old })
	saml.RandReader = &covShortReader{}

	assert.Check(t, is.DeepEqual([]byte{1, 2, 3, 4, 5, 6, 7, 8}, randomBytes(8)))
}

func TestCovGetSPMetadata(t *testing.T) {
	_, err := getSPMetadata(covErrReader{})
	assert.Check(t, is.ErrorContains(err, "cov: read failure"))

	// wrong root element
	_, err = getSPMetadata(strings.NewReader(`<Foo xmlns="urn:oasis:names:tc:SAML:2.0:metadata"></Foo>`))
	assert.Check(t, is.ErrorContains(err, "expected element type <EntityDescriptor> but have <Foo>"))

	// EntitiesDescriptor containing an SP
	spMetadata, err := getSPMetadata(strings.NewReader(`` +
		`<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">` +
		`<EntityDescriptor entityID="https://idp.example.com/"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"></IDPSSODescriptor></EntityDescriptor>` +
		`<EntityDescriptor entityID="https://sp.example.com/"><SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"></SPSSODescriptor></EntityDescriptor>` +
		`</EntitiesDescriptor>`))
	assert.NilError(t, err)
	assert.Check(t, is.Equal("https://sp.example.com/", spMetadata.EntityID))

	// EntitiesDescriptor without any SP
	_, err = getSPMetadata(strings.NewReader(`` +
		`<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">` +
		`<EntityDescriptor entityID="https://idp.example.com/"></EntityDescriptor>` +
		`</EntitiesDescriptor>`))
	assert.Check(t, is.Error(err, "metadata contained no service provider metadata"))

	// EntitiesDescriptor that cannot be parsed
	_, err = getSPMetadata(strings.NewReader(`` +
		`<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" validUntil="not a time">` +
		`</EntitiesDescriptor>`))
	assert.Check(t, err != nil)
	assert.Check(t, err.Error() != "metadata contained no service provider metadata")
}
