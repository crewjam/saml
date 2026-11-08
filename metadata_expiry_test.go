package saml

import (
	"encoding/base64"
	"errors"
	"testing"
	"time"

	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/v3/assert"
)

// saml-metadata-2.0-os §4.3.1: metadata must not be relied on past its
// validUntil. With RejectExpiredIDPMetadata the SP refuses messages whose
// signing certificates come from expired IdP metadata; without it (the
// default) such metadata is still trusted, as before.
func TestRejectExpiredIDPMetadata(t *testing.T) {
	past := spcovNow.Add(-24 * time.Hour)
	future := spcovNow.Add(24 * time.Hour)

	expireEntity := func(e *spcovEnv) { e.sp.IDPMetadata.ValidUntil = past }
	expireRole := func(e *spcovEnv) { e.sp.IDPMetadata.IDPSSODescriptors[0].ValidUntil = &past }
	unexpired := func(e *spcovEnv) {
		e.sp.IDPMetadata.ValidUntil = future
		e.sp.IDPMetadata.IDPSSODescriptors[0].ValidUntil = &future
	}

	// each message is checked with the IdP metadata changed by mutate
	messages := map[string]func(t *testing.T, e *spcovEnv) error{
		"Response": func(t *testing.T, e *spcovEnv) error {
			_, err := e.sp.ParseXMLResponse(e.signedResponse(t), []string{spcovRequestID}, e.sp.AcsURL)
			return err
		},
		"LogoutResponse POST": func(t *testing.T, e *spcovEnv) error {
			buf := spcovSerialize(t, e.idpSign(t, e.logoutResponse().Element()))
			return e.sp.ValidateLogoutResponseForm(base64.StdEncoding.EncodeToString(buf))
		},
		"LogoutResponse redirect": func(t *testing.T, e *spcovEnv) error {
			q := redirectQuery{param: "SAMLResponse", xml: e.unsignedLogoutResponse(t), sigAlg: dsig.RSASHA256SignatureMethod, key: e.idpKey}
			return e.sp.ValidateLogoutResponseRequest(redirectRequest(e.sp, q.build(t)))
		},
		"LogoutRequest redirect": func(t *testing.T, e *spcovEnv) error {
			q := redirectQuery{param: "SAMLRequest", xml: spcovSerialize(t, e.logoutRequest().Element()), sigAlg: dsig.RSASHA256SignatureMethod, key: e.idpKey}
			_, err := e.sp.ValidateLogoutRequest(redirectRequest(e.sp, q.build(t)))
			return err
		},
	}

	for name, check := range messages {
		t.Run(name, func(t *testing.T) {
			t.Run("default accepts expired metadata", func(t *testing.T) {
				e := spcovSetup(t)
				expireEntity(e)
				expireRole(e)
				assert.NilError(t, check(t, e))
			})

			t.Run("expired EntityDescriptor refused", func(t *testing.T) {
				e := spcovSetup(t)
				e.sp.RejectExpiredIDPMetadata = true
				expireEntity(e)
				err := check(t, e)
				assert.Assert(t, err != nil)
				assert.Check(t, errors.Is(err, ErrExpired), "%v", err)
			})

			t.Run("expired IDPSSODescriptor refused", func(t *testing.T) {
				e := spcovSetup(t)
				e.sp.RejectExpiredIDPMetadata = true
				expireRole(e)
				err := check(t, e)
				assert.Assert(t, err != nil)
				assert.Check(t, errors.Is(err, ErrExpired), "%v", err)
			})

			t.Run("unexpired accepted", func(t *testing.T) {
				e := spcovSetup(t)
				e.sp.RejectExpiredIDPMetadata = true
				unexpired(e)
				assert.NilError(t, check(t, e))
			})

			t.Run("no validUntil accepted", func(t *testing.T) {
				e := spcovSetup(t)
				e.sp.RejectExpiredIDPMetadata = true
				assert.NilError(t, check(t, e))
			})
		})
	}

	t.Run("Response error is classified", func(t *testing.T) {
		e := spcovSetup(t)
		e.sp.RejectExpiredIDPMetadata = true
		expireEntity(e)
		_, err := e.sp.ParseXMLResponse(e.signedResponse(t), []string{spcovRequestID}, e.sp.AcsURL)
		assert.Error(t, spcovPrivateErr(t, err),
			"cannot validate signature on Response: IDP metadata expired at 2013-12-31T00:00:00Z")
		assert.Check(t, errors.Is(err, ErrExpired))
		assert.Check(t, errors.Is(err, ErrInvalidSignature))
	})

	t.Run("validUntil is exclusive", func(t *testing.T) {
		e := spcovSetup(t)
		e.sp.RejectExpiredIDPMetadata = true
		e.sp.IDPMetadata.ValidUntil = spcovNow
		_, err := e.sp.ParseXMLResponse(e.signedResponse(t), []string{spcovRequestID}, e.sp.AcsURL)
		assert.Check(t, errors.Is(err, ErrExpired), "%v", err)
	})

	t.Run("IDPCertificate set: metadata not relied on for keys", func(t *testing.T) {
		e := spcovSetup(t)
		e.sp.RejectExpiredIDPMetadata = true
		expireEntity(e)
		cert := base64.StdEncoding.EncodeToString(e.idpCert.Raw)
		e.sp.IDPCertificate = &cert
		_, err := e.sp.ParseXMLResponse(e.signedResponse(t), []string{spcovRequestID}, e.sp.AcsURL)
		assert.NilError(t, err)
	})

	t.Run("expired metadata does not block endpoint lookup or outgoing messages", func(t *testing.T) {
		e := spcovSetup(t)
		e.sp.RejectExpiredIDPMetadata = true
		expireEntity(e)
		destination := e.sp.GetSSOBindingLocation(HTTPRedirectBinding)
		assert.Assert(t, destination != "")

		_, err := e.sp.MakeAuthenticationRequest(destination, HTTPRedirectBinding, HTTPPostBinding)
		assert.NilError(t, err)
		_, err = e.sp.MakeLogoutResponse(destination, "request-id")
		assert.NilError(t, err)
	})

	t.Run("expired unrelated role does not block SSO verification", func(t *testing.T) {
		e := spcovSetup(t)
		e.sp.RejectExpiredIDPMetadata = true
		e.sp.IDPMetadata.PDPDescriptors = []PDPDescriptor{{
			RoleDescriptor: RoleDescriptor{ValidUntil: &past},
		}}
		_, err := e.sp.ParseXMLResponse(e.signedResponse(t), []string{spcovRequestID}, e.sp.AcsURL)
		assert.NilError(t, err)
	})

	t.Run("attribute authority", func(t *testing.T) {
		e := spcovSetup(t)
		e.sp.RejectExpiredIDPMetadata = true
		e.sp.IDPMetadata.AttributeAuthorityDescriptors = []AttributeAuthorityDescriptor{{
			RoleDescriptor: RoleDescriptor{
				ValidUntil:     &past,
				KeyDescriptors: e.sp.IDPMetadata.IDPSSODescriptors[0].KeyDescriptors,
			},
		}}
		_, err := e.sp.attributeAuthoritySigningCerts()
		assert.Check(t, errors.Is(err, ErrExpired), "%v", err)

		e.sp.IDPMetadata.AttributeAuthorityDescriptors[0].ValidUntil = &future
		certs, err := e.sp.attributeAuthoritySigningCerts()
		assert.NilError(t, err)
		assert.Check(t, len(certs) == 1)

		e.sp.IDPMetadata.ValidUntil = past
		_, err = e.sp.attributeAuthoritySigningCerts()
		assert.Check(t, errors.Is(err, ErrExpired), "%v", err)
	})

	t.Run("expired unused attribute authority does not block a valid authority", func(t *testing.T) {
		e := spcovSetup(t)
		e.sp.RejectExpiredIDPMetadata = true
		e.sp.IDPMetadata.AttributeAuthorityDescriptors = []AttributeAuthorityDescriptor{
			{
				RoleDescriptor: RoleDescriptor{ValidUntil: &past, KeyDescriptors: e.sp.IDPMetadata.IDPSSODescriptors[0].KeyDescriptors},
			},
			{
				RoleDescriptor: RoleDescriptor{ValidUntil: &future, KeyDescriptors: e.sp.IDPMetadata.IDPSSODescriptors[0].KeyDescriptors},
			},
		}
		certs, err := e.sp.attributeAuthoritySigningCerts()
		assert.NilError(t, err)
		assert.Equal(t, len(certs), 1)
	})
}
