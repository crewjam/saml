package samlidp

import (
	"bytes"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml"
)

// spMetadataXML returns the metadata of a service provider with entity ID
// entityID.
func spMetadataXML(t *testing.T, test *ServerTest, entityID string) []byte {
	t.Helper()
	sp := saml.ServiceProvider{
		Key:         test.SPKey,
		Certificate: test.SPCertificate,
		EntityID:    entityID,
		MetadataURL: mustParseURL(entityID),
		AcsURL:      mustParseURL(entityID + "/acs"),
	}
	data, err := xml.Marshal(sp.Metadata())
	assert.NilError(t, err)
	return data
}

func serveService(t *testing.T, test *ServerTest, method, id string, body []byte) int {
	t.Helper()
	w := httptest.NewRecorder()
	r, _ := http.NewRequest(method, "https://idp.example.com/services/"+id, bytes.NewReader(body))
	test.Server.ServeHTTP(w, r)
	return w.Code
}

func isRegistered(test *ServerTest, entityID string) bool {
	_, err := test.Server.GetServiceProvider(nil, entityID)
	return err == nil
}

// Replacing a service's metadata with metadata of another entity ID stops
// accepting the old entity ID.
func TestPutServiceReplacesPreviousEntity(t *testing.T) {
	test := NewServerTest(t)
	const a, b = "https://a.example.com/metadata", "https://b.example.com/metadata"

	assert.Check(t, is.Equal(http.StatusNoContent, serveService(t, test, "PUT", "x", spMetadataXML(t, test, a))))
	assert.Check(t, isRegistered(test, a))

	assert.Check(t, is.Equal(http.StatusNoContent, serveService(t, test, "PUT", "x", spMetadataXML(t, test, b))))
	assert.Check(t, !isRegistered(test, a), "the replaced entity is still accepted")
	assert.Check(t, isRegistered(test, b))

	assert.Check(t, is.Equal(http.StatusNoContent, serveService(t, test, "DELETE", "x", nil)))
	assert.Check(t, !isRegistered(test, b))
}

// Deleting one of two services with the same entity ID keeps the entity
// accepted with the other one's metadata.
func TestDeleteServiceKeepsEntityRegisteredElsewhere(t *testing.T) {
	test := NewServerTest(t)
	const a = "https://a.example.com/metadata"

	assert.Check(t, is.Equal(http.StatusNoContent, serveService(t, test, "PUT", "x", spMetadataXML(t, test, a))))
	assert.Check(t, is.Equal(http.StatusNoContent, serveService(t, test, "PUT", "y", spMetadataXML(t, test, a))))

	assert.Check(t, is.Equal(http.StatusNoContent, serveService(t, test, "DELETE", "x", nil)))
	assert.Check(t, isRegistered(test, a), "the entity is still stored as y")

	assert.Check(t, is.Equal(http.StatusNoContent, serveService(t, test, "DELETE", "y", nil)))
	assert.Check(t, !isRegistered(test, a))
}

// A server started on an existing store tracks the stored services by ID.
func TestPutServiceReplacesEntityLoadedFromStore(t *testing.T) {
	test := NewServerTest(t)
	const a, b = "https://a.example.com/metadata", "https://b.example.com/metadata"
	assert.Check(t, is.Equal(http.StatusNoContent, serveService(t, test, "PUT", "x", spMetadataXML(t, test, a))))

	restarted, err := New(Options{
		Certificate: test.Certificate,
		Key:         test.Key,
		Store:       &test.Store,
		URL:         test.Server.IDP.SSOURL,
	})
	assert.NilError(t, err)
	test.Server = restarted
	assert.Check(t, isRegistered(test, a))

	assert.Check(t, is.Equal(http.StatusNoContent, serveService(t, test, "PUT", "x", spMetadataXML(t, test, b))))
	assert.Check(t, !isRegistered(test, a))
	assert.Check(t, isRegistered(test, b))
}
