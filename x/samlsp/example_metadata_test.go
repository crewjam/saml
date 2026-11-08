package samlsp_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlsp"
)

// spKey and spCert are the SP's key pair in the examples. A real
// application loads them from its configuration.
var spKey, spCert = func() (*rsa.PrivateKey, *x509.Certificate) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sp.example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return key, cert
}()

// t0 is the context of the examples that do not run in a handler.
func t0() context.Context { return context.Background() }

// RemoteMetadata fetches the IdP metadata when it is first needed, and
// again when it gets stale, which picks up rotated signing certificates.
func ExampleRemoteMetadata() {
	config, err := samlsp.New(
		"https://sp.example.com/saml/metadata",
		samlsp.RemoteMetadata("https://idp.example.com/metadata",
			samlsp.WithHTTPClient(&http.Client{Timeout: 10 * time.Second}),
			samlsp.WithRefreshInterval(6*time.Hour)))
	if err != nil {
		log.Fatal(err)
	}
	_ = config
}

// A federation publishes the metadata of many entities in one signed
// aggregate. Select the IdP by its entity ID, and check the federation's
// signature.
func ExampleRemoteMetadata_federation() {
	var federationCert *x509.Certificate // the federation's signing certificate

	idp := samlsp.RemoteMetadata("https://federation.example.org/metadata.xml",
		samlsp.WithIdentityProviderEntityID("https://idp.university.example.edu/idp/shibboleth"),
		samlsp.WithMetadataSigners(federationCert))

	entityID := "https://sp.example.com/saml/metadata"
	config, err := samlsp.New(entityID, idp)
	if err != nil {
		log.Fatal(err)
	}
	_ = config
}

// StaticMetadataBytes uses metadata that the application already has, such
// as a file the IdP administrator sent.
func ExampleStaticMetadataBytes() {
	data := []byte(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com/metadata">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`)

	entityID := "https://sp.example.com/saml/metadata"
	config, err := samlsp.New(entityID, samlsp.StaticMetadataBytes(data))
	if err != nil {
		log.Fatal(err)
	}
	msg, err := config.AuthnRequest(t0(), "relay-state")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(msg.Destination)
	// Output:
	// https://idp.example.com/sso
}

// Metadata in a file, read when the program starts.
func ExampleStaticMetadataBytes_file() {
	data, err := os.ReadFile("idp-metadata.xml")
	if err != nil {
		log.Fatal(err)
	}
	entityID := "https://sp.example.com/saml/metadata"
	config, err := samlsp.New(entityID, samlsp.StaticMetadataBytes(data))
	if err != nil {
		log.Fatal(err)
	}
	_ = config
}

type tenantKey struct{}

// A MetadataFunc can be any function. Here, one Config serves many
// tenants, each with its own IdP: the function picks the tenant's metadata
// by the tenant that middleware put in the request context.
func ExampleMetadataFunc() {
	tenants := map[string]samlsp.MetadataFunc{
		"acme":    samlsp.RemoteMetadata("https://acme.okta.example/app/123/sso/saml/metadata"),
		"initech": samlsp.RemoteMetadata("https://login.initech.example/federationmetadata.xml"),
	}
	idp := func(ctx context.Context) (*saml.EntityDescriptor, error) {
		tenant, _ := ctx.Value(tenantKey{}).(string)
		md, ok := tenants[tenant]
		if !ok {
			return nil, errors.New("unknown tenant")
		}
		return md(ctx)
	}

	entityID := "https://sp.example.com/saml/metadata"
	config, err := samlsp.New(entityID, idp)
	if err != nil {
		log.Fatal(err)
	}

	withTenant := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), tenantKey{}, r.PathValue("tenant"))
			next(w, r.WithContext(ctx))
		}
	}
	http.HandleFunc("/{tenant}/login", withTenant(func(w http.ResponseWriter, r *http.Request) {
		msg, err := config.AuthnRequest(r.Context(), rand.Text())
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		// remember msg.ID, msg.RelayState and the tenant
		msg.Write(w)
	}))
}

// WithHTTPClient sets the HTTP client for the requests the SP makes to the
// IdP: here, one that authenticates with a TLS client certificate, to
// resolve HTTP-Artifact responses. The same option sets the client of
// RemoteMetadata.
func ExampleWithHTTPClient() {
	var mtlsClient *http.Client // configured with the SP's client certificate

	config, err := samlsp.New(
		"https://sp.example.com/saml/metadata",
		samlsp.RemoteMetadata("https://idp.example.com/metadata", samlsp.WithHTTPClient(mtlsClient)),
		samlsp.WithSigningKey(spKey, spCert),
		samlsp.WithHTTPClient(mtlsClient))
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc(config.ACSPath(), func(w http.ResponseWriter, r *http.Request) {
		assertion, err := config.ParseResponse(r.Context(), r, samlsp.WithRequestID(takePendingRequest(r)))
		if err != nil {
			http.Error(w, "login failed", http.StatusForbidden)
			return
		}
		startSession(w, assertion)
	})

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		msg, err := config.AuthnRequest(r.Context(), rand.Text(),
			samlsp.WithResponseBinding(saml.HTTPArtifactBinding))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		msg.Write(w)
	})
}
