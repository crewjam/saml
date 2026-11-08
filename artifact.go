package saml

import (
	"crypto/sha1" //nolint:gosec // G505: SHA-1 is how saml-bindings §3.6.4 defines the SourceID
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

// artifactTypeCode4 is the TypeCode of the only artifact format SAML 2.0
// defines (saml-bindings-2.0-os §3.6.4.1).
const artifactTypeCode4 = 0x0004

// artifactType4Length is the length of a decoded type 0x0004 artifact: a
// 2-byte TypeCode, a 2-byte EndpointIndex, a 20-byte SourceID and a 20-byte
// MessageHandle.
const artifactType4Length = 2 + 2 + 20 + 20

// artifactReplayKeyPrefix is prepended to the key an artifact is recorded
// under in an AssertionReplayCache. Like logoutRequestReplayKeyPrefix, it
// keeps artifacts apart from assertion IDs, which contain no colon.
const artifactReplayKeyPrefix = "Artifact:"

// maxArtifactLength is the longest SAMLart value, in bytes, that checkArtifact
// accepts. A type 0x0004 artifact is 60 characters of base64; the bound
// leaves room for other formats while keeping an attacker from filling the
// ReplayCache with large keys, or sending large ArtifactResolve requests to
// the IdP, before anything about the request is authenticated.
const maxArtifactLength = 256

// samlArtifact is a decoded type 0x0004 SAML artifact
// (saml-bindings-2.0-os §3.6.4).
type samlArtifact struct {
	EndpointIndex uint16
	SourceID      [20]byte
	MessageHandle [20]byte
}

// decodeArtifact decodes the base64 SAMLart value s as a type 0x0004
// artifact. The error matches ErrMalformedMessage when s is not base64 of
// 44 bytes, and ErrUnsupported when its TypeCode is not 0x0004.
func decodeArtifact(s string) (*samlArtifact, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, classify(fmt.Errorf("artifact is not valid base64: %w", err), ErrMalformedMessage)
	}
	if len(raw) < 2 {
		return nil, classify(fmt.Errorf("artifact is %d bytes long, too short for a TypeCode", len(raw)), ErrMalformedMessage)
	}
	if typeCode := binary.BigEndian.Uint16(raw[0:2]); typeCode != artifactTypeCode4 {
		return nil, classify(fmt.Errorf("artifact has TypeCode 0x%04x, only 0x0004 is supported", typeCode), ErrUnsupported)
	}
	if len(raw) != artifactType4Length {
		return nil, classify(fmt.Errorf("type 0x0004 artifact is %d bytes long, expected %d", len(raw), artifactType4Length), ErrMalformedMessage)
	}
	a := &samlArtifact{EndpointIndex: binary.BigEndian.Uint16(raw[2:4])}
	copy(a.SourceID[:], raw[4:24])
	copy(a.MessageHandle[:], raw[24:44])
	return a, nil
}

// artifactSourceID returns the SourceID an IdP with entityID puts in its
// artifacts: the SHA-1 hash of its entity ID (saml-bindings-2.0-os §3.6.4.1).
func artifactSourceID(entityID string) [20]byte {
	return sha1.Sum([]byte(entityID)) //nolint:gosec // G401: mandated by saml-bindings §3.6.4.1
}

// artifactResolutionLocation returns the location of the IdP's SOAP
// ArtifactResolutionService for artifact. When artifact is a decoded type
// 0x0004 artifact and an indexed SOAP ArtifactResolutionService of the IdP
// metadata has its EndpointIndex, that endpoint is used
// (saml-bindings-2.0-os §3.6.4.1, §3.6.5.2). Otherwise it is the first
// SOAP ArtifactResolutionService, as GetArtifactBindingLocation returns.
func (sp *ServiceProvider) artifactResolutionLocation(artifact *samlArtifact) string {
	if artifact != nil && sp.IDPMetadata != nil {
		for _, idpSSODescriptor := range sp.IDPMetadata.IDPSSODescriptors {
			for _, ars := range idpSSODescriptor.SSODescriptor.ArtifactResolutionServices {
				if ars.Binding == SOAPBinding && ars.Index == int(artifact.EndpointIndex) {
					return ars.Location
				}
			}
		}
	}
	if location := sp.GetArtifactBindingLocation(SOAPBinding); location != "" {
		return location
	}
	if sp.IDPMetadata != nil {
		for _, idpSSODescriptor := range sp.IDPMetadata.IDPSSODescriptors {
			for _, ars := range idpSSODescriptor.SSODescriptor.ArtifactResolutionServices {
				if ars.Binding == SOAPBinding {
					return ars.Location
				}
			}
		}
	}
	return ""
}

// checkArtifact decodes the SAMLart value artifactID and checks it against
// the IdP metadata. It returns the decoded artifact, or nil when
// artifactID is not a type 0x0004 artifact and RequireStandardArtifacts is
// false. Whatever RequireStandardArtifacts says, an artifact longer than
// maxArtifactLength or with bytes outside printable ASCII is refused.
func (sp *ServiceProvider) checkArtifact(artifactID string) (*samlArtifact, error) {
	if len(artifactID) > maxArtifactLength {
		return nil, classify(fmt.Errorf("artifact is %d bytes long, longer than %d", len(artifactID), maxArtifactLength), ErrMalformedMessage)
	}
	for i := 0; i < len(artifactID); i++ {
		if c := artifactID[i]; c <= ' ' || c > '~' {
			return nil, classify(fmt.Errorf("artifact contains the byte 0x%02x, which is not printable ASCII", c), ErrMalformedMessage)
		}
	}
	artifact, err := decodeArtifact(artifactID)
	if err != nil {
		if sp.RequireStandardArtifacts {
			return nil, err
		}
		return nil, nil
	}
	if sp.RequireStandardArtifacts {
		if sp.IDPMetadata == nil || sp.IDPMetadata.EntityID == "" {
			return nil, classify(errors.New("cannot check the artifact SourceID: the IdP metadata has no entityID"), ErrMissingElement)
		}
		want := artifactSourceID(sp.IDPMetadata.EntityID)
		if subtle.ConstantTimeCompare(want[:], artifact.SourceID[:]) != 1 {
			return nil, classify(fmt.Errorf("artifact SourceID %x is not the SHA-1 hash of the IdP entityID %q", artifact.SourceID, sp.IDPMetadata.EntityID), ErrIssuerMismatch)
		}
	}
	return artifact, nil
}

// consumeArtifact records the artifact in the ReplayCache, if one is set,
// refusing it if it was recorded before. A type 0x0004 artifact is recorded
// by its SourceID and MessageHandle, so that the same message cannot be
// resolved again through another EndpointIndex; any other artifact by its
// value. The record is kept for the issue delay (see maxIssueDelay), which bounds how long an
// IdP should keep an artifact resolvable (saml-bindings-2.0-os §3.6.5.2).
// It is called only once the artifact has resolved to a verified Response,
// because anyone can make a SAMLart with the right SourceID.
func (sp *ServiceProvider) consumeArtifact(artifactID string, artifact *samlArtifact) error {
	if sp.ReplayCache == nil {
		return nil
	}
	key := artifactReplayKeyPrefix + "raw:" + artifactID
	if artifact != nil {
		key = artifactReplayKeyPrefix + hex.EncodeToString(artifact.SourceID[:]) + ":" + hex.EncodeToString(artifact.MessageHandle[:])
	}
	if err := sp.ReplayCache.Consume(key, sp.now().Add(sp.maxIssueDelay())); err != nil {
		return fmt.Errorf("artifact: %w", err)
	}
	return nil
}
