package saml

import (
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // G505: the artifact SourceID is a SHA-1 hash
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// artifactdecMake returns a base64 type 0x0004 artifact
// (saml-bindings-2.0-os §3.6.4.1) with the given EndpointIndex, SourceID and
// a MessageHandle filled with handle.
func artifactdecMake(index uint16, sourceID [20]byte, handle byte) string {
	raw := make([]byte, 4, 44)
	binary.BigEndian.PutUint16(raw[0:2], 0x0004)
	binary.BigEndian.PutUint16(raw[2:4], index)
	raw = append(raw, sourceID[:]...)
	raw = append(raw, bytes.Repeat([]byte{handle}, 20)...)
	return base64.StdEncoding.EncodeToString(raw)
}

func artifactdecIDPSourceID() [20]byte {
	return sha1.Sum([]byte(spcovIDPEntityID)) //nolint:gosec // G401: SourceID
}

// artifactdecServer is an artifact resolution service that answers any
// artifact at any path, and records the paths and artifacts it was sent.
type artifactdecServer struct {
	srv       *httptest.Server
	paths     []string
	artifacts []string
}

func artifactdecSetup(t *testing.T) (*spcovEnv, *artifactdecServer) {
	t.Helper()
	e := spcovSetup(t)
	s := &artifactdecServer{}
	s.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := etree.NewDocument()
		if _, err := doc.ReadFrom(r.Body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resolveEl := doc.FindElement("//ArtifactResolve")
		if resolveEl == nil {
			http.Error(w, "no ArtifactResolve", http.StatusBadRequest)
			return
		}
		s.paths = append(s.paths, r.URL.Path)
		s.artifacts = append(s.artifacts, resolveEl.FindElement("./Artifact").Text())
		el := e.artifactResponseEl(t, resolveEl.SelectAttrValue("ID", ""), true, nil)
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write(spcovSerialize(t, spcovSOAPEnvelope(el)))
	}))
	t.Cleanup(s.srv.Close)
	e.sp.HTTPClient = s.srv.Client()

	idp := &e.sp.IDPMetadata.IDPSSODescriptors[0]
	// The unindexed list (what IDP metadata parses into today) names a
	// default endpoint; the indexed list names one endpoint per index.
	idp.ArtifactResolutionServices = []Endpoint{
		{Binding: SOAPBinding, Location: s.srv.URL + "/default"},
	}
	idp.SSODescriptor.ArtifactResolutionServices = []IndexedEndpoint{
		{Binding: HTTPPostBinding, Location: s.srv.URL + "/not-soap", Index: 7},
		{Binding: SOAPBinding, Location: s.srv.URL + "/ars0", Index: 0},
		{Binding: SOAPBinding, Location: s.srv.URL + "/ars7", Index: 7},
	}
	return e, s
}

// saml-bindings-2.0-os §3.6.4.1: the EndpointIndex of a type 0x0004
// artifact identifies the artifact resolution endpoint the requester must
// use, and §3.6.5.2 has the requester send its ArtifactResolve there.
func TestArtifactDecodingEndpointIndex(t *testing.T) {
	e, s := artifactdecSetup(t)

	t.Run("index names an indexed SOAP endpoint", func(t *testing.T) {
		s.paths = nil
		artifact := artifactdecMake(7, artifactdecIDPSourceID(), 0x01)
		assertion, err := e.sp.ParseResponse(spcovArtifactRequest(artifact), []string{spcovRequestID})
		assert.NilError(t, err)
		assert.Check(t, is.Equal("alice@example.com", assertion.Subject.NameID.Value))
		assert.Check(t, is.DeepEqual([]string{"/ars7"}, s.paths))
		assert.Check(t, is.Equal(artifact, s.artifacts[len(s.artifacts)-1]))
	})

	t.Run("index zero", func(t *testing.T) {
		s.paths = nil
		_, err := e.sp.ParseResponse(spcovArtifactRequest(artifactdecMake(0, artifactdecIDPSourceID(), 0x02)), []string{spcovRequestID})
		assert.NilError(t, err)
		assert.Check(t, is.DeepEqual([]string{"/ars0"}, s.paths))
	})

	t.Run("no endpoint has the index: first SOAP endpoint", func(t *testing.T) {
		s.paths = nil
		_, err := e.sp.ParseResponse(spcovArtifactRequest(artifactdecMake(9, artifactdecIDPSourceID(), 0x03)), []string{spcovRequestID})
		assert.NilError(t, err)
		assert.Check(t, is.DeepEqual([]string{"/default"}, s.paths))
	})

	t.Run("non-standard artifact: first SOAP endpoint", func(t *testing.T) {
		s.paths = nil
		_, err := e.sp.ParseResponse(spcovArtifactRequest("the-artifact"), []string{spcovRequestID})
		assert.NilError(t, err)
		assert.Check(t, is.DeepEqual([]string{"/default"}, s.paths))
	})

	t.Run("only indexed endpoints, no index match: first indexed SOAP endpoint", func(t *testing.T) {
		s.paths = nil
		sp := *e.sp
		md := *sp.IDPMetadata
		md.IDPSSODescriptors = append([]IDPSSODescriptor(nil), md.IDPSSODescriptors...)
		md.IDPSSODescriptors[0].ArtifactResolutionServices = nil
		sp.IDPMetadata = &md
		_, err := sp.ParseResponse(spcovArtifactRequest(artifactdecMake(9, artifactdecIDPSourceID(), 0x04)), []string{spcovRequestID})
		assert.NilError(t, err)
		assert.Check(t, is.DeepEqual([]string{"/ars0"}, s.paths))
	})
}

// By default, artifacts that are not type 0x0004 artifacts of this IdP are
// still sent to the IdP unchanged, as before; with RequireStandardArtifacts
// they are refused without contacting the IdP.
func TestArtifactDecodingStrictness(t *testing.T) {
	e, s := artifactdecSetup(t)

	wrongSource := sha1.Sum([]byte("https://other-idp.example.com/metadata")) //nolint:gosec // G401: SourceID
	tooLong := base64.StdEncoding.EncodeToString(append(append([]byte{0x00, 0x04, 0x00, 0x00}, make([]byte, 40)...), 0x00))
	type0002 := base64.StdEncoding.EncodeToString(append([]byte{0x00, 0x02, 0x00, 0x00}, make([]byte, 40)...))
	cases := []struct {
		name     string
		artifact string
		kind     error
		msg      string
	}{
		{"not base64", "the-artifact", ErrMalformedMessage, "invalid artifact: artifact is not valid base64: illegal base64 data at input byte 3"},
		{"too short", base64.StdEncoding.EncodeToString([]byte{0x00}), ErrMalformedMessage, "invalid artifact: artifact is 1 bytes long, too short for a TypeCode"},
		{"wrong length", tooLong, ErrMalformedMessage, "invalid artifact: type 0x0004 artifact is 45 bytes long, expected 44"},
		{"wrong TypeCode", type0002, ErrUnsupported, "invalid artifact: artifact has TypeCode 0x0002, only 0x0004 is supported"},
		{"wrong SourceID", artifactdecMake(0, wrongSource, 0x05), ErrIssuerMismatch, ""},
	}

	for _, c := range cases {
		t.Run(c.name+" is sent unchanged by default", func(t *testing.T) {
			s.artifacts = nil
			_, err := e.sp.ParseResponse(spcovArtifactRequest(c.artifact), []string{spcovRequestID})
			assert.NilError(t, err)
			assert.Check(t, is.DeepEqual([]string{c.artifact}, s.artifacts))
		})
		t.Run(c.name+" is refused with RequireStandardArtifacts", func(t *testing.T) {
			s.artifacts = nil
			sp := *e.sp
			sp.RequireStandardArtifacts = true
			_, err := sp.ParseResponse(spcovArtifactRequest(c.artifact), []string{spcovRequestID})
			privateErr := spcovPrivateErr(t, err)
			assert.Check(t, is.ErrorIs(privateErr, ErrArtifactResolution))
			assert.Check(t, is.ErrorIs(privateErr, c.kind))
			if c.msg != "" {
				assert.Check(t, is.Error(privateErr, c.msg))
			}
			assert.Check(t, is.Len(s.artifacts, 0), "the IdP must not be contacted")
		})
	}

	t.Run("standard artifact is accepted with RequireStandardArtifacts", func(t *testing.T) {
		s.paths = nil
		sp := *e.sp
		sp.RequireStandardArtifacts = true
		_, err := sp.ParseResponse(spcovArtifactRequest(artifactdecMake(7, artifactdecIDPSourceID(), 0x06)), []string{spcovRequestID})
		assert.NilError(t, err)
		assert.Check(t, is.DeepEqual([]string{"/ars7"}, s.paths))
	})

	t.Run("IdP metadata without entityID", func(t *testing.T) {
		sp := *e.sp
		sp.RequireStandardArtifacts = true
		md := *sp.IDPMetadata
		md.EntityID = ""
		sp.IDPMetadata = &md
		_, err := sp.handleArtifactRequest(context.Background(), artifactdecMake(7, artifactdecIDPSourceID(), 0x07), nil)
		privateErr := spcovPrivateErr(t, err)
		assert.Check(t, is.ErrorIs(privateErr, ErrArtifactResolution))
		assert.Check(t, is.ErrorIs(privateErr, ErrMissingElement))
	})
}

// saml-bindings-2.0-os §3.6.5.2: an artifact is resolved only once. With a
// ReplayCache, the SP refuses a second resolution of the same artifact
// before contacting the IdP.
func TestArtifactDecodingReplay(t *testing.T) {
	e, s := artifactdecSetup(t)
	cache := memoryReplayCache{}
	e.sp.ReplayCache = cache

	artifact := artifactdecMake(7, artifactdecIDPSourceID(), 0x08)
	_, err := e.sp.ParseResponse(spcovArtifactRequest(artifact), []string{spcovRequestID})
	assert.NilError(t, err)
	assert.Check(t, is.Len(s.paths, 1))
	_, recorded := cache["Artifact:"+bytesHex(artifactdecIDPSourceID())+":"+bytesHex(fill20(0x08))]
	assert.Check(t, recorded, "cache keys: %v", cache)
	_, recorded = cache["id-assertion"]
	assert.Check(t, recorded)

	t.Run("same artifact again", func(t *testing.T) {
		_, err := e.sp.ParseResponse(spcovArtifactRequest(artifact), []string{spcovRequestID})
		privateErr := spcovPrivateErr(t, err)
		assert.Check(t, is.ErrorIs(privateErr, ErrArtifactResolution))
		assert.Check(t, is.ErrorIs(privateErr, ErrAssertionReplayed))
		assert.Check(t, is.Len(s.paths, 1), "the IdP must not be contacted again")
	})

	t.Run("same MessageHandle through another EndpointIndex", func(t *testing.T) {
		_, err := e.sp.ParseResponse(spcovArtifactRequest(artifactdecMake(0, artifactdecIDPSourceID(), 0x08)), []string{spcovRequestID})
		assert.Check(t, is.ErrorIs(spcovPrivateErr(t, err), ErrAssertionReplayed))
		assert.Check(t, is.Len(s.paths, 1))
	})

	t.Run("non-standard artifact is recorded by value", func(t *testing.T) {
		delete(cache, "id-assertion")
		_, err := e.sp.ParseResponse(spcovArtifactRequest("the-artifact"), []string{spcovRequestID})
		assert.NilError(t, err)
		_, recorded := cache["Artifact:raw:the-artifact"]
		assert.Check(t, recorded)
		_, err = e.sp.ParseResponse(spcovArtifactRequest("the-artifact"), []string{spcovRequestID})
		assert.Check(t, is.ErrorIs(spcovPrivateErr(t, err), ErrAssertionReplayed))
		assert.Check(t, is.Len(s.paths, 2))
	})

	t.Run("cache error refuses the artifact", func(t *testing.T) {
		sp := *e.sp
		sp.ReplayCache = failingReplayCache{}
		_, err := sp.ParseResponse(spcovArtifactRequest(artifactdecMake(7, artifactdecIDPSourceID(), 0x09)), []string{spcovRequestID})
		privateErr := spcovPrivateErr(t, err)
		assert.Check(t, is.ErrorIs(privateErr, ErrArtifactResolution))
		assert.Check(t, is.Error(privateErr, "artifact: store unavailable"))
		assert.Check(t, !errors.Is(privateErr, ErrAssertionReplayed))
		assert.Check(t, is.Len(s.paths, 2))
	})
}

func fill20(b byte) [20]byte {
	var a [20]byte
	copy(a[:], bytes.Repeat([]byte{b}, 20))
	return a
}

func bytesHex(a [20]byte) string { return hex.EncodeToString(a[:]) }
