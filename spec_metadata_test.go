package saml

import (
	"encoding/base64"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// Tests in this file pin behavior required by the OASIS SAML V2.0 Metadata
// specification (saml-metadata-2.0-os) and the "Use of Metadata" sections of
// the profiles specification (saml-profiles-2.0-os).

// specMetadataSP returns a service provider configured like the one in
// NewIdentityProviderTest, with an IdP to talk to.
func specMetadataSP(t *testing.T) *ServiceProvider {
	t.Helper()
	test := NewServiceProviderTest(t)
	sp := &ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("https://sp.example.com/saml2/metadata"),
		AcsURL:      mustParseURL("https://sp.example.com/saml2/acs"),
		SloURL:      mustParseURL("https://sp.example.com/saml2/slo"),
		IDPMetadata: &EntityDescriptor{},
	}
	assert.NilError(t, xml.Unmarshal(test.IDPMetadata, sp.IDPMetadata))
	return sp
}

// marshalMetadataDoc marshals v and parses it with etree, for checks on the
// XML a consumer actually sees.
func marshalMetadataDoc(t *testing.T, v interface{}) *etree.Element {
	t.Helper()
	buf, err := xml.Marshal(v)
	assert.NilError(t, err)
	doc := etree.NewDocument()
	assert.NilError(t, doc.ReadFromBytes(buf))
	return doc.Root()
}

// saml-metadata-2.0-os §2.3.2 (lines 406-407): "When used as the root element
// of a metadata instance, this element MUST contain either a validUntil or
// cacheDuration attribute." The IdP's metadata carries both.
func TestSpecMetadata_2_3_2_IdPRootHasValidUntilOrCacheDuration(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	root := marshalMetadataDoc(t, test.IDP.Metadata())
	assert.Check(t, is.Equal("EntityDescriptor", root.Tag))
	assert.Check(t, root.SelectAttr("validUntil") != nil)
	assert.Check(t, root.SelectAttr("cacheDuration") != nil)
	// cacheDuration is an xsd:duration, not a count of nanoseconds.
	assert.Check(t, strings.HasPrefix(root.SelectAttrValue("cacheDuration", ""), "P"))

	// It is also present on the metadata served over HTTP.
	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", test.IDP.MetadataURL.String(), nil)
	test.IDP.ServeMetadata(w, r)
	doc := etree.NewDocument()
	assert.NilError(t, doc.ReadFromBytes(w.Body.Bytes()))
	assert.Check(t, doc.Root().SelectAttr("validUntil") != nil || doc.Root().SelectAttr("cacheDuration") != nil)
}

// saml-metadata-2.0-os §2.3.2 (lines 406-407): the root EntityDescriptor MUST
// contain either a validUntil or a cacheDuration attribute. The SP metadata
// carries validUntil by default, and cacheDuration when validUntil is
// omitted with MetadataOmitValidUntil.
func TestSpecMetadata_2_3_2_SPRootHasValidUntilOrCacheDuration(t *testing.T) {
	sp := specMetadataSP(t)

	root := marshalMetadataDoc(t, sp.Metadata())
	assert.Check(t, root.SelectAttr("validUntil") != nil)

	sp.MetadataOmitValidUntil = true
	root = marshalMetadataDoc(t, sp.Metadata())
	assert.Check(t, root.SelectAttr("validUntil") == nil)
	cacheDuration := root.SelectAttrValue("cacheDuration", "")
	assert.Check(t, strings.HasPrefix(cacheDuration, "P"), "cacheDuration=%q", cacheDuration)

	// and the duration reads back as DefaultCacheDuration
	var ed EntityDescriptor
	buf, err := xml.Marshal(sp.Metadata())
	assert.NilError(t, err)
	assert.NilError(t, xml.Unmarshal(buf, &ed))
	assert.Check(t, is.Equal(DefaultCacheDuration, ed.CacheDuration))
}

// saml-metadata-2.0-os §2.4.1 (lines 563-566): protocolSupportEnumeration is
// required, and "For SAML V2.0 entities, this set MUST include the SAML
// protocol namespace URI, urn:oasis:names:tc:SAML:2.0:protocol."
func TestSpecMetadata_2_4_1_ProtocolSupportEnumerationIncludesSAML2(t *testing.T) {
	const samlp = "urn:oasis:names:tc:SAML:2.0:protocol"
	test := NewIdentityProviderTest(t, applyKey)

	for name, ed := range map[string]*EntityDescriptor{
		"idp": test.IDP.Metadata(),
		"sp":  test.SP.Metadata(),
	} {
		root := marshalMetadataDoc(t, ed)
		descriptors := root.SelectElements("IDPSSODescriptor")
		descriptors = append(descriptors, root.SelectElements("SPSSODescriptor")...)
		assert.Check(t, is.Len(descriptors, 1), name)
		for _, d := range descriptors {
			attr := d.SelectAttr("protocolSupportEnumeration")
			assert.Assert(t, attr != nil, name)
			assert.Check(t, is.Contains(strings.Fields(attr.Value), samlp), name)
		}
	}
}

// saml-metadata-2.0-os §2.4.3 (lines 690-693): an IDPSSODescriptor has one
// or more SingleSignOnService elements, and "The ResponseLocation attribute
// MUST be omitted." WantAuthnRequestsSigned is optional; the IdP, which does
// not verify XML signatures on AuthnRequests, does not claim to require them.
func TestSpecMetadata_2_4_3_IdPSingleSignOnServiceHasNoResponseLocation(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.AdvertiseSimpleSignSSO = true
	root := marshalMetadataDoc(t, test.IDP.Metadata())
	idpsso := root.SelectElement("IDPSSODescriptor")
	assert.Assert(t, idpsso != nil)

	ssos := idpsso.SelectElements("SingleSignOnService")
	assert.Check(t, len(ssos) >= 1)
	for _, sso := range ssos {
		assert.Check(t, sso.SelectAttr("Binding") != nil)
		assert.Check(t, sso.SelectAttrValue("Location", "") != "")
		assert.Check(t, sso.SelectAttr("ResponseLocation") == nil)
	}
	assert.Check(t, idpsso.SelectAttr("WantAuthnRequestsSigned") == nil)
}

// saml-metadata-2.0-os §2.4.4 (lines 748-751) and §2.2.3 (lines 264-268): an
// SPSSODescriptor has one or more AssertionConsumerService elements, each an
// IndexedEndpointType with a required index that is unique among them.
func TestSpecMetadata_2_4_4_SPAssertionConsumerServicesAreIndexed(t *testing.T) {
	sp := specMetadataSP(t)
	sp.AssertionConsumerServiceBindings = []string{HTTPPostBinding, HTTPArtifactBinding, HTTPPostSimpleSignBinding}
	root := marshalMetadataDoc(t, sp.Metadata())
	spsso := root.SelectElement("SPSSODescriptor")
	assert.Assert(t, spsso != nil)

	acss := spsso.SelectElements("AssertionConsumerService")
	assert.Check(t, is.Len(acss, 3))
	seen := map[string]bool{}
	for _, acs := range acss {
		index := acs.SelectAttr("index")
		assert.Assert(t, index != nil)
		n, err := strconv.Atoi(index.Value)
		assert.Check(t, err)
		assert.Check(t, n >= 0 && n <= 65535, "index is an xs:unsignedShort")
		assert.Check(t, !seen[index.Value], "duplicate index %s", index.Value)
		seen[index.Value] = true
		assert.Check(t, acs.SelectAttr("Binding") != nil)
		assert.Check(t, is.Equal(sp.AcsURL.String(), acs.SelectAttrValue("Location", "")))
	}
}

// saml-metadata-2.0-os §2.4.4 (lines 740-742): AuthnRequestsSigned "indicates
// whether the <samlp:AuthnRequest> messages sent by this service provider will
// be signed." Profiles §4.1.6 (lines 622-624): it documents "the intention to
// sign all of its requests". The SP advertises true exactly when it signs.
func TestSpecMetadata_2_4_4_SPAuthnRequestsSignedMatchesSigning(t *testing.T) {
	sp := specMetadataSP(t)

	md := sp.Metadata()
	assert.Assert(t, md.SPSSODescriptors[0].AuthnRequestsSigned != nil)
	assert.Check(t, !*md.SPSSODescriptors[0].AuthnRequestsSigned)
	req, err := sp.MakeAuthenticationRequest(sp.GetSSOBindingLocation(HTTPPostBinding), HTTPPostBinding, HTTPPostBinding)
	assert.NilError(t, err)
	assert.Check(t, req.Signature == nil)

	sp.SignatureMethod = dsig.RSASHA256SignatureMethod
	md = sp.Metadata()
	assert.Assert(t, md.SPSSODescriptors[0].AuthnRequestsSigned != nil)
	assert.Check(t, *md.SPSSODescriptors[0].AuthnRequestsSigned)

	// HTTP-POST: the request carries an enveloped XML signature.
	req, err = sp.MakeAuthenticationRequest(sp.GetSSOBindingLocation(HTTPPostBinding), HTTPPostBinding, HTTPPostBinding)
	assert.NilError(t, err)
	assert.Check(t, req.Signature != nil)

	// HTTP-Redirect: the query string is signed.
	u, err := sp.MakeRedirectAuthenticationRequest("relay")
	assert.NilError(t, err)
	assert.Check(t, u.Query().Get("Signature") != "")
	assert.Check(t, is.Equal(dsig.RSASHA256SignatureMethod, u.Query().Get("SigAlg")))

	// The SP signing key is published with use="signing" (profiles §4.1.6
	// lines 625-626).
	var signing []KeyDescriptor
	for _, kd := range md.SPSSODescriptors[0].KeyDescriptors {
		if kd.Use == "signing" {
			signing = append(signing, kd)
		}
	}
	assert.Assert(t, is.Len(signing, 1))
	assert.Check(t, is.Equal(base64.StdEncoding.EncodeToString(sp.Certificate.Raw),
		signing[0].KeyInfo.X509Data.X509Certificates[0].Data))
}

// saml-metadata-2.0-os §2.4.1.1 (lines 615-617, 636-641): the use attribute of
// a KeyDescriptor is optional and its values are drawn from the KeyTypes
// enumeration, "encryption" and "signing". Metadata generated by the library
// only uses those two values.
func TestSpecMetadata_2_4_1_1_GeneratedKeyDescriptorUseValues(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	test.SP.SignatureMethod = dsig.RSASHA256SignatureMethod

	for name, ed := range map[string]*EntityDescriptor{
		"idp": test.IDP.Metadata(),
		"sp":  test.SP.Metadata(),
	} {
		root := marshalMetadataDoc(t, ed)
		kds := root.FindElements("./*/KeyDescriptor")
		assert.Check(t, len(kds) >= 2, name)
		uses := map[string]bool{}
		for _, kd := range kds {
			use := kd.SelectAttrValue("use", "")
			assert.Check(t, use == "signing" || use == "encryption", "%s: use=%q", name, use)
			uses[use] = true
			// ds:KeyInfo is required (line 618, 630)
			assert.Check(t, kd.SelectElement("KeyInfo") != nil, name)
		}
		assert.Check(t, uses["signing"] && uses["encryption"], name)
	}
}

// saml-metadata-2.0-os §2.4.1.1 (lines 615-617): use is optional; a key
// without it is not restricted to one purpose. Profiles §4.1.6 (lines
// 625-626): signing keys are documented with use="signing". When verifying
// IdP signatures the SP trusts keys with use="signing" or no use, and never a
// key published only for encryption.
func TestSpecMetadata_2_4_1_1_SigningKeySelectionByUse(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	idpCert := base64.StdEncoding.EncodeToString(test.Certificate.Raw)
	spCert := base64.StdEncoding.EncodeToString(test.SPCertificate.Raw)
	kd := func(use, cert string) KeyDescriptor {
		return KeyDescriptor{Use: use, KeyInfo: KeyInfo{X509Data: X509Data{
			X509Certificates: []X509Certificate{{Data: cert}}}}}
	}

	certs, err := signingCerts([]KeyDescriptor{kd("signing", idpCert), kd("encryption", spCert)})
	assert.NilError(t, err)
	assert.Assert(t, is.Len(certs, 1))
	assert.Check(t, certs[0].Equal(test.Certificate))

	certs, err = signingCerts([]KeyDescriptor{kd("", idpCert)})
	assert.NilError(t, err)
	assert.Assert(t, is.Len(certs, 1))
	assert.Check(t, certs[0].Equal(test.Certificate))

	certs, err = signingCerts([]KeyDescriptor{kd("encryption", idpCert)})
	assert.NilError(t, err)
	assert.Check(t, is.Len(certs, 0))

	// getIDPSigningCerts fails rather than falling back to an encryption key.
	test.SP.IDPMetadata = &EntityDescriptor{IDPSSODescriptors: []IDPSSODescriptor{{
		SSODescriptor: SSODescriptor{RoleDescriptor: RoleDescriptor{
			KeyDescriptors: []KeyDescriptor{kd("encryption", idpCert)},
		}},
	}}}
	_, err = test.SP.getIDPSigningCerts()
	assert.Check(t, err != nil)
}

// saml-metadata-2.0-os §2.4.1.1 (lines 612-617) and profiles §4.1.6 (lines
// 626-628): keys used to receive encryption keys are documented with
// use="encryption"; a KeyDescriptor without use may serve either purpose.
// When encrypting to the SP, the IdP picks a use="encryption" key first,
// then one without use, and never a use="signing" key.
func TestSpecMetadata_2_4_1_1_EncryptionKeySelectionByUse(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	idpCert := base64.StdEncoding.EncodeToString(test.Certificate.Raw)
	spCert := base64.StdEncoding.EncodeToString(test.SPCertificate.Raw)
	kd := func(use, cert string) KeyDescriptor {
		return KeyDescriptor{Use: use, KeyInfo: KeyInfo{X509Data: X509Data{
			X509Certificates: []X509Certificate{{Data: cert}}}}}
	}
	reqWith := func(kds ...KeyDescriptor) *IdpAuthnRequest {
		return &IdpAuthnRequest{SPSSODescriptor: &SPSSODescriptor{
			SSODescriptor: SSODescriptor{RoleDescriptor: RoleDescriptor{KeyDescriptors: kds}},
		}}
	}

	// use="encryption" wins over a key without use listed before it
	cert, err := reqWith(kd("", idpCert), kd("encryption", spCert)).getSPEncryptionCert()
	assert.NilError(t, err)
	assert.Check(t, cert.Equal(test.SPCertificate))

	// a key without use is used for encryption
	cert, err = reqWith(kd("signing", idpCert), kd("", spCert)).getSPEncryptionCert()
	assert.NilError(t, err)
	assert.Check(t, cert.Equal(test.SPCertificate))

	// a signing-only key is never used for encryption
	_, err = reqWith(kd("signing", spCert)).getSPEncryptionCert()
	assert.Check(t, err != nil)
}

// saml-metadata-2.0-os §2.2.3 (lines 272-273): "the default endpoint is the
// first such endpoint with the isDefault attribute set to true." Core
// §3.4.1 (errata lines 2129-2130): without an ACS index or URL the IdP MUST
// return the response to the default location. The IdP selects the
// isDefault="true" endpoint even when it is not listed first.
func TestSpecMetadata_2_2_3_DefaultEndpointIsFirstWithIsDefaultTrue(t *testing.T) {
	tr := true
	req := IdpAuthnRequest{ServiceProviderMetadata: &EntityDescriptor{SPSSODescriptors: []SPSSODescriptor{{
		AssertionConsumerServices: []IndexedEndpoint{
			{Binding: HTTPPostBinding, Location: "https://sp.example.com/acs/1", Index: 1},
			{Binding: HTTPPostBinding, Location: "https://sp.example.com/acs/2", Index: 2, IsDefault: &tr},
			{Binding: HTTPPostBinding, Location: "https://sp.example.com/acs/3", Index: 3, IsDefault: &tr},
		},
	}}}}
	assert.NilError(t, req.getACSEndpoint())
	assert.Check(t, is.Equal("https://sp.example.com/acs/2", req.ACSEndpoint.Location))
}

// saml-metadata-2.0-os §2.2.3 (lines 269-275): isDefault is optional and
// assumed false when omitted; if no endpoint is marked default, the first
// one is the default.
func TestSpecMetadata_2_2_3_DefaultEndpointWithoutIsDefaultIsFirst(t *testing.T) {
	req := IdpAuthnRequest{ServiceProviderMetadata: &EntityDescriptor{SPSSODescriptors: []SPSSODescriptor{{
		AssertionConsumerServices: []IndexedEndpoint{
			{Binding: HTTPPostBinding, Location: "https://sp.example.com/acs/1", Index: 5},
			{Binding: HTTPPostBinding, Location: "https://sp.example.com/acs/2", Index: 1},
		},
	}}}}
	assert.NilError(t, req.getACSEndpoint())
	assert.Check(t, is.Equal("https://sp.example.com/acs/1", req.ACSEndpoint.Location))

	// An omitted isDefault is not serialized, and is read back as unset.
	buf, err := xml.Marshal(req.ServiceProviderMetadata.SPSSODescriptors[0].AssertionConsumerServices[0])
	assert.NilError(t, err)
	assert.Check(t, !strings.Contains(string(buf), "isDefault"))
	var ep IndexedEndpoint
	assert.NilError(t, xml.Unmarshal(buf, &ep))
	assert.Check(t, ep.IsDefault == nil)
}

// saml-metadata-2.0-os §2.2.3 (lines 264-266) and profiles §4.1.6 (lines
// 629-632): the index attribute distinguishes ACS endpoints that "may be
// specified by reference in the <AuthnRequest> message"; the IdP sends the
// response to the endpoint whose index the request names.
func TestSpecMetadata_2_2_3_EndpointSelectedByIndex(t *testing.T) {
	tr := true
	req := IdpAuthnRequest{
		Request: AuthnRequest{AssertionConsumerServiceIndex: "7"},
		ServiceProviderMetadata: &EntityDescriptor{SPSSODescriptors: []SPSSODescriptor{{
			AssertionConsumerServices: []IndexedEndpoint{
				{Binding: HTTPPostBinding, Location: "https://sp.example.com/acs/default", Index: 1, IsDefault: &tr},
				{Binding: HTTPPostBinding, Location: "https://sp.example.com/acs/7", Index: 7},
			},
		}}},
	}
	assert.NilError(t, req.getACSEndpoint())
	assert.Check(t, is.Equal("https://sp.example.com/acs/7", req.ACSEndpoint.Location))
}

// saml-metadata-2.0-os §2.2.2 (lines 229-237): EndpointType carries Binding,
// Location and an optional ResponseLocation. Profiles §4.1.6 (lines 618-620)
// and §4.4.5 (lines 1312-1313): the SP picks the IdP's SingleSignOnService
// and SingleLogoutService endpoint by binding.
func TestSpecMetadata_2_2_2_EndpointSelectedByBinding(t *testing.T) {
	input := `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com/metadata" validUntil="2030-01-01T00:00:00Z">` +
		`<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
		`<SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/slo/post" ResponseLocation="https://idp.example.com/slo/post-response"/>` +
		`<SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/slo/redirect"/>` +
		`<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/sso/post"/>` +
		`<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso/redirect"/>` +
		`</IDPSSODescriptor></EntityDescriptor>`
	sp := ServiceProvider{IDPMetadata: &EntityDescriptor{}}
	assert.NilError(t, xml.Unmarshal([]byte(input), sp.IDPMetadata))

	assert.Check(t, is.Equal("https://idp.example.com/sso/redirect", sp.GetSSOBindingLocation(HTTPRedirectBinding)))
	assert.Check(t, is.Equal("https://idp.example.com/sso/post", sp.GetSSOBindingLocation(HTTPPostBinding)))
	assert.Check(t, is.Equal("", sp.GetSSOBindingLocation(HTTPArtifactBinding)))
	assert.Check(t, is.Equal("https://idp.example.com/slo/redirect", sp.GetSLOBindingLocation(HTTPRedirectBinding)))
	assert.Check(t, is.Equal("https://idp.example.com/slo/post", sp.GetSLOBindingLocation(HTTPPostBinding)))

	slo := sp.IDPMetadata.IDPSSODescriptors[0].SingleLogoutServices
	assert.Check(t, is.Equal("https://idp.example.com/slo/post-response", slo[0].ResponseLocation))
	assert.Check(t, is.Equal("", slo[1].ResponseLocation))
}

// saml-metadata-2.0-os §2.2.4 and §2.2.5 (lines 285-305): localizedNameType
// and localizedURIType carry a required xml:lang attribute, in the XML
// namespace.
func TestSpecMetadata_2_2_4_LocalizedNameUsesXMLLang(t *testing.T) {
	org := Organization{
		OrganizationNames:        []LocalizedName{{Lang: "en", Value: "Example"}},
		OrganizationDisplayNames: []LocalizedName{{Lang: "de", Value: "Beispiel"}},
		OrganizationURLs:         []LocalizedURI{{Lang: "en", Value: "https://example.com/"}},
	}
	buf, err := xml.Marshal(org)
	assert.NilError(t, err)
	assert.Check(t, is.Contains(string(buf), `<OrganizationName xml:lang="en">Example</OrganizationName>`))
	assert.Check(t, is.Contains(string(buf), `<OrganizationDisplayName xml:lang="de">Beispiel</OrganizationDisplayName>`))
	assert.Check(t, is.Contains(string(buf), `<OrganizationURL xml:lang="en">https://example.com/</OrganizationURL>`))

	input := `<AttributeConsumingService xmlns="urn:oasis:names:tc:SAML:2.0:metadata" index="1">` +
		`<ServiceName xml:lang="fr">Service</ServiceName>` +
		`<ServiceDescription xml:lang="en">Description</ServiceDescription>` +
		`<RequestedAttribute Name="mail" isRequired="true"/>` +
		`</AttributeConsumingService>`
	var acs AttributeConsumingService
	assert.NilError(t, xml.Unmarshal([]byte(input), &acs))
	assert.Check(t, is.DeepEqual([]LocalizedName{{Lang: "fr", Value: "Service"}}, acs.ServiceNames))
	assert.Check(t, is.DeepEqual([]LocalizedName{{Lang: "en", Value: "Description"}}, acs.ServiceDescriptions))
	// §2.4.4.2 (lines 813-815): isRequired is an optional boolean.
	assert.Assert(t, is.Len(acs.RequestedAttributes, 1))
	assert.Assert(t, acs.RequestedAttributes[0].IsRequired != nil)
	assert.Check(t, *acs.RequestedAttributes[0].IsRequired)
}

// saml-metadata-2.0-os §3.1 (lines 1181-1207): signed metadata uses an
// enveloped signature (1181); the signed element supplies an identifier
// attribute (1185); the signature has a single ds:Reference whose URI is
// "#" followed by that identifier (1188-1190); exclusive canonicalization is
// used (1194, SHOULD); and no transforms other than the enveloped-signature
// and exclusive canonicalization transforms appear (1199, SHOULD NOT).
func TestSpecMetadata_3_1_SignedMetadataProfile(t *testing.T) {
	const (
		envelopedTransform = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
		excC14N            = "http://www.w3.org/2001/10/xml-exc-c14n#"
		excC14NComments    = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"
	)
	idpTest := NewIdentityProviderTest(t, applyKey)
	idpSigned, err := idpTest.IDP.SignedMetadata()
	assert.NilError(t, err)

	sp := specMetadataSP(t)
	spSigned, err := sp.SignedMetadata()
	assert.NilError(t, err)

	for name, el := range map[string]*etree.Element{
		"idp": idpSigned,
		"sp":  spSigned,
	} {
		id := el.SelectAttrValue("ID", "")
		assert.Check(t, id != "", name)

		// enveloped: the Signature is a child of the signed element
		sig := el.SelectElement("Signature")
		assert.Assert(t, sig != nil, name)
		assert.Check(t, is.Equal("Signature", el.ChildElements()[0].Tag), name)

		refs := sig.FindElements("./SignedInfo/Reference")
		assert.Assert(t, is.Len(refs, 1), name)
		assert.Check(t, is.Equal("#"+id, refs[0].SelectAttrValue("URI", "")), name)

		c14n := sig.FindElement("./SignedInfo/CanonicalizationMethod")
		assert.Assert(t, c14n != nil, name)
		alg := c14n.SelectAttrValue("Algorithm", "")
		assert.Check(t, alg == excC14N || alg == excC14NComments, "%s: %s", name, alg)

		transforms := refs[0].FindElements("./Transforms/Transform")
		assert.Check(t, len(transforms) >= 1, name)
		sawEnveloped := false
		for _, tr := range transforms {
			alg := tr.SelectAttrValue("Algorithm", "")
			switch alg {
			case envelopedTransform:
				sawEnveloped = true
			case excC14N, excC14NComments:
			default:
				t.Errorf("%s: unexpected transform %s", name, alg)
			}
		}
		assert.Check(t, sawEnveloped, name)
	}

	// and both signatures verify as served
	validateSignedMetadata(t, idpSigned, idpTest.Certificate)
	validateSignedMetadata(t, spSigned, sp.Certificate)
}

// saml-metadata-2.0-os §3.1.2 (lines 1185-1190): "Signed metadata elements
// MUST supply a value for the identifier attribute on the signed element."
// An ID already present on the EntityDescriptor is the one referenced.
func TestSpecMetadata_3_1_2_SignatureReferencesExistingID(t *testing.T) {
	sp := specMetadataSP(t)
	ed := sp.Metadata()
	ed.ID = "_my-metadata-id"
	ctx, err := sp.signingContext(dsig.RSASHA256SignatureMethod)
	assert.NilError(t, err)
	el, err := signMetadata(ed, ctx, nil)
	assert.NilError(t, err)
	assert.Check(t, is.Equal("_my-metadata-id", el.SelectAttrValue("ID", "")))
	ref := el.FindElement("./Signature/SignedInfo/Reference")
	assert.Assert(t, ref != nil)
	assert.Check(t, is.Equal("#_my-metadata-id", ref.SelectAttrValue("URI", "")))
	// the caller's EntityDescriptor is not modified
	assert.Check(t, ed.Signature == nil)
	validateSignedMetadata(t, el, sp.Certificate)
}

// saml-metadata-2.0-os §4.1.1 (lines 1234-1235): "If the publishing protocol
// permits MIME-based identification of content types, the content type of the
// metadata instance MUST be application/samlmetadata+xml." This holds for
// both unsigned and signed IdP metadata.
func TestSpecMetadata_4_1_1_MetadataContentType(t *testing.T) {
	for _, signed := range []bool{false, true} {
		test := NewIdentityProviderTest(t, applyKey)
		test.IDP.SignMetadata = signed
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("GET", test.IDP.MetadataURL.String(), nil)
		test.IDP.ServeMetadata(w, r)
		assert.Check(t, is.Equal(http.StatusOK, w.Code))
		assert.Check(t, is.Equal("application/samlmetadata+xml", w.Header().Get("Content-Type")), "signed=%v", signed)

		// §4.1.1 (lines 1236-1238): the root is an EntityDescriptor whose
		// entityID is the location the metadata is published at.
		var ed EntityDescriptor
		assert.NilError(t, xml.Unmarshal(w.Body.Bytes(), &ed))
		assert.Check(t, is.Equal(test.IDP.MetadataURL.String(), ed.EntityID))
	}
}

// saml-metadata-2.0-os §2.4.2 (lines 648-651) and §2.2.3: the
// ArtifactResolutionService of an SPSSODescriptor is an indexed endpoint;
// its index and isDefault attributes are kept when parsed and re-serialized.
func TestSpecMetadata_2_4_2_SPArtifactResolutionServiceIsIndexed(t *testing.T) {
	input := `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com/metadata" cacheDuration="PT1H">` +
		`<SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
		`<ArtifactResolutionService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://sp.example.com/ars" index="3" isDefault="true"/>` +
		`<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/acs" index="0"/>` +
		`</SPSSODescriptor></EntityDescriptor>`
	var ed EntityDescriptor
	assert.NilError(t, xml.Unmarshal([]byte(input), &ed))
	ars := ed.SPSSODescriptors[0].ArtifactResolutionServices
	assert.Assert(t, is.Len(ars, 1))
	assert.Check(t, is.Equal(3, ars[0].Index))
	assert.Assert(t, ars[0].IsDefault != nil)
	assert.Check(t, *ars[0].IsDefault)

	buf, err := xml.Marshal(ed)
	assert.NilError(t, err)
	assert.Check(t, is.Contains(string(buf), `index="3" isDefault="true"`))
}
