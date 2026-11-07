package saml

// Tests pinning behaviour required by OASIS SAML V2.0 Core (saml-core-2.0-os,
// with the approved errata sstc-saml-core-errata-2.0-wd-07) §1.3 (common data
// types), §2 (assertions), §4 (versioning) and §8 (identifiers).

import (
	crand "crypto/rand"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml/xmlenc"
)

// specCoreSignedResponse returns a Response signed by the IDP that carries a
// (plaintext, unsigned) assertion. mutate, if set, edits the Assertion
// element before the Response is signed.
func specCoreSignedResponse(t *testing.T, e *spcovEnv, a *Assertion, mutate func(assertionEl *etree.Element)) []byte {
	t.Helper()
	r := e.response()
	r.Assertion = a
	el := r.Element()
	if mutate != nil {
		assertionEl := el.FindElement("./Assertion")
		assert.Assert(t, assertionEl != nil)
		mutate(assertionEl)
	}
	return spcovSerialize(t, e.idpSign(t, el))
}

// specCoreIDPRequest returns a validated IdpAuthnRequest from
// NewIdentityProviderTest, issued at 2015-12-01T01:57:09Z. It restores the globals
// NewIdentityProviderTest changes.
func specCoreIDPRequest(t *testing.T) *IdpAuthnRequest {
	t.Helper()
	oldTimeNow, oldRandReader, oldXMLEncRandReader := TimeNow, RandReader, xmlenc.RandReader
	t.Cleanup(func() {
		TimeNow, RandReader, xmlenc.RandReader = oldTimeNow, oldRandReader, oldXMLEncRandReader
	})
	test := NewIdentityProviderTest(t, applyKey)
	req := &IdpAuthnRequest{
		Now: TimeNow(),
		IDP: &test.IDP,
		RequestBuffer: []byte(`<AuthnRequest xmlns="urn:oasis:names:tc:SAML:2.0:protocol"` +
			` AssertionConsumerServiceURL="https://sp.example.com/saml2/acs"` +
			` Destination="https://idp.example.com/saml/sso"` +
			` ID="id-00020406080a0c0e10121416181a1c1e"` +
			` IssueInstant="2015-12-01T01:57:09Z" Version="2.0">` +
			`<Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">https://sp.example.com/saml2/metadata</Issuer>` +
			`</AuthnRequest>`),
	}
	var err error
	req.HTTPRequest, err = http.NewRequest(http.MethodPost, "https://idp.example.com/saml/sso", nil)
	assert.NilError(t, err)
	assert.NilError(t, req.Validate())
	return req
}

// saml-core §1.3.3 (lines 311-312): SAML time values "MUST be expressed in
// UTC form, with no time zone component". Every time a message or assertion
// writes is converted to UTC, whatever the zone of the time.Time it holds:
// one taken from a request (Conditions NotBefore is the AuthnRequest's
// IssueInstant) or from the application (AuthnInstant is
// Session.CreateTime).
func TestSpecCore_1_3_3_TimesInOtherZonesWrittenAsUTC(t *testing.T) {
	east := time.FixedZone("UTC+5", 5*3600)
	west := time.FixedZone("UTC-7", -7*3600)
	at := time.Date(2015, 12, 1, 1, 57, 9, 0, time.UTC)
	inEast, inWest := at.In(east), at.In(west)
	const want = "2015-12-01T01:57:09Z"

	checkTimes := func(t *testing.T, el *etree.Element) {
		t.Helper()
		seen := 0
		var walk func(el *etree.Element)
		walk = func(el *etree.Element) {
			for _, attr := range el.Attr {
				switch attr.Key {
				case "IssueInstant", "NotBefore", "NotOnOrAfter", "AuthnInstant", "SessionNotOnOrAfter":
					seen++
					assert.Check(t, strings.HasSuffix(attr.Value, "Z"), "%s/@%s = %s", el.Tag, attr.Key, attr.Value)
				}
			}
			for _, child := range el.ChildElements() {
				walk(child)
			}
		}
		walk(el)
		assert.Check(t, seen > 0)
	}

	t.Run("every message type", func(t *testing.T) {
		for name, el := range map[string]*etree.Element{
			"AuthnRequest":    (&AuthnRequest{IssueInstant: inEast}).Element(),
			"LogoutRequest":   (&LogoutRequest{IssueInstant: inEast, NotOnOrAfter: &inWest}).Element(),
			"LogoutResponse":  (&LogoutResponse{IssueInstant: inWest}).Element(),
			"ArtifactResolve": (&ArtifactResolve{IssueInstant: inEast}).Element(),
			"ArtifactResponse": (&ArtifactResponse{IssueInstant: inWest,
				Response: Response{IssueInstant: inEast}}).Element(),
			"AttributeQuery": (&AttributeQuery{IssueInstant: inEast,
				Subject: &Subject{NameID: &NameID{Value: "alice"}}}).Element(),
			"Assertion": (&Assertion{IssueInstant: inEast,
				Subject: &Subject{SubjectConfirmations: []SubjectConfirmation{{
					SubjectConfirmationData: &SubjectConfirmationData{NotBefore: inWest, NotOnOrAfter: inEast},
				}}},
				Conditions:      &Conditions{NotBefore: inWest, NotOnOrAfter: inEast},
				AuthnStatements: []AuthnStatement{{AuthnInstant: inWest, SessionNotOnOrAfter: &inEast}},
			}).Element(),
		} {
			t.Run(name, func(t *testing.T) {
				checkTimes(t, el)
				assert.Check(t, is.Equal(want, el.SelectAttrValue("IssueInstant", "")))
			})
		}
	})

	t.Run("IdP assertion from a request and session in other zones", func(t *testing.T) {
		req := specCoreIDPRequest(t)
		req.Request.IssueInstant = req.Request.IssueInstant.In(east)
		session := &Session{ID: "x", NameID: "n", CreateTime: TimeNow().In(west)}
		assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, session))
		el := req.Assertion.Element()
		checkTimes(t, el)
		assert.Check(t, is.Equal("2015-12-01T01:57:09Z", el.FindElement("./Conditions").SelectAttrValue("NotBefore", "")))
	})
}

// saml-core §1.3.1 (lines 280-283): "all elements in SAML documents that have
// the XML Schema xs:string type ... MUST be compared using an exact binary
// comparison. In particular, SAML implementations ... MUST NOT depend on
// case-insensitive string comparisons, normalization or trimming of
// whitespace". The Issuer of an assertion is compared exactly.
func TestSpecCore_1_3_1_IssuerExactComparison(t *testing.T) {
	now := TimeNow()
	sp := requiredConditionsSP()
	for _, issuer := range []string{
		"HTTPS://IDP.EXAMPLE.COM/",
		"https://idp.example.com",
		" https://idp.example.com/",
		"https://idp.example.com/ ",
	} {
		a := validAssertion(now)
		a.Issuer.Value = issuer
		err := sp.validateAssertion(a, []string{"id-1"}, now)
		assert.Check(t, errors.Is(err, ErrIssuerMismatch), "issuer %q: %v", issuer, err)
	}
}

// saml-core §1.3.1 (lines 280-283), exact binary comparison, applied to the
// Audience URI (§2.5.1.4) and the SubjectConfirmationData Recipient
// (§2.4.1.2).
func TestSpecCore_1_3_1_AudienceAndRecipientExactComparison(t *testing.T) {
	now := TimeNow()
	sp := requiredConditionsSP()

	for _, audience := range []string{"https://SP.example.com/metadata", "https://sp.example.com/metadata/", "https://sp.example.com/metadata "} {
		a := validAssertion(now)
		a.Conditions.AudienceRestrictions[0].Audience.Value = audience
		err := sp.validateAssertion(a, []string{"id-1"}, now)
		assert.Check(t, errors.Is(err, ErrAudienceMismatch), "audience %q: %v", audience, err)
	}

	for _, recipient := range []string{"https://SP.example.com/acs", "https://sp.example.com/acs/", " https://sp.example.com/acs"} {
		a := validAssertion(now)
		a.Subject.SubjectConfirmations[0].SubjectConfirmationData.Recipient = recipient
		err := sp.validateAssertion(a, []string{"id-1"}, now)
		assert.Check(t, errors.Is(err, ErrDestinationMismatch), "recipient %q: %v", recipient, err)
	}
}

// saml-core §1.3.3 (lines 311-312): "All SAML time values ... MUST be
// expressed in UTC form, with no time zone component." The IdP's assertion
// and the SP's AuthnRequest (with the default UTC clock) carry only
// "Z"-suffixed times.
func TestSpecCore_1_3_3_GeneratedTimesAreUTC(t *testing.T) {
	req := specCoreIDPRequest(t)
	assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{
		ID: "f00d", NameID: "n", CreateTime: TimeNow(), Index: "1",
	}))
	el := req.Assertion.Element()
	utc := regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,3})?Z$`)
	for _, path := range []struct{ el, attr string }{
		{".", "IssueInstant"},
		{"./Conditions", "NotBefore"},
		{"./Conditions", "NotOnOrAfter"},
		{"./Subject/SubjectConfirmation/SubjectConfirmationData", "NotOnOrAfter"},
		{"./AuthnStatement", "AuthnInstant"},
	} {
		child := el.FindElement(path.el)
		assert.Assert(t, child != nil, path.el)
		v := child.SelectAttrValue(path.attr, "")
		assert.Check(t, utc.MatchString(v), "%s/@%s = %q", path.el, path.attr, v)
	}

	e := spcovSetup(t)
	authnReq, err := e.sp.MakeAuthenticationRequest("https://idp.example.com/sso/post", HTTPPostBinding, HTTPPostBinding)
	assert.NilError(t, err)
	v := authnReq.Element().SelectAttrValue("IssueInstant", "")
	assert.Check(t, utc.MatchString(v), "AuthnRequest/@IssueInstant = %q", v)
}

// saml-core §1.3.4 (lines 319-329): identifiers MUST have a negligible
// probability of collision; a random identifier MUST have collision
// probability <= 2^-128 and SHOULD have <= 2^-160 ("encoding a randomly
// chosen value between 128 and 160 bits"), and "The encoding must conform to
// the rules defining the xs:ID datatype" (an NCName). Assertion and request
// IDs are "id-" followed by 160 random bits in hex.
func TestSpecCore_1_3_4_GeneratedIDsAreRandomNCNames(t *testing.T) {
	ncname160 := regexp.MustCompile(`^id-[0-9a-f]{40}$`)

	seen := map[string]bool{}
	check := func(id string) {
		t.Helper()
		assert.Check(t, ncname160.MatchString(id), "id %q", id)
		assert.Check(t, !seen[id], "duplicate id %q", id)
		seen[id] = true
	}

	for i := 0; i < 3; i++ {
		req := specCoreIDPRequest(t)
		RandReader = crand.Reader
		assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "f00d", NameID: "n"}))
		check(req.Assertion.ID)
	}

	e := spcovSetup(t)
	RandReader = crand.Reader
	for i := 0; i < 3; i++ {
		authnReq, err := e.sp.MakeAuthenticationRequest("https://idp.example.com/sso/post", HTTPPostBinding, HTTPPostBinding)
		assert.NilError(t, err)
		check(authnReq.ID)
	}
}

// saml-core errata E92 (§1.3.3, errata lines 359-361): "SAML system entities
// SHOULD allow for reasonable clock skew ... Tolerances of 3-5 minutes are
// reasonable defaults, but allowing for configurability is a suggested
// practice". MaxClockSkew is a configurable variable whose default is in that
// range, and it is applied to both NotBefore and NotOnOrAfter (§2.5.1.2 E92).
func TestSpecCore_1_3_3_E92_ClockSkewTolerance(t *testing.T) {
	assert.Check(t, MaxClockSkew >= 3*time.Minute && MaxClockSkew <= 5*time.Minute, "MaxClockSkew = %s", MaxClockSkew)

	now := TimeNow()
	sp := requiredConditionsSP()

	a := validAssertion(now)
	a.Conditions.NotBefore = now.Add(MaxClockSkew - time.Second)
	assert.Check(t, sp.validateAssertion(a, []string{"id-1"}, now), "NotBefore within skew in the future")

	a = validAssertion(now)
	a.Conditions.NotOnOrAfter = now.Add(-MaxClockSkew + time.Second)
	assert.Check(t, sp.validateAssertion(a, []string{"id-1"}, now), "NotOnOrAfter within skew in the past")

	a = validAssertion(now)
	a.Subject.SubjectConfirmations[0].SubjectConfirmationData.NotOnOrAfter = now.Add(-MaxClockSkew + time.Second)
	assert.Check(t, sp.validateAssertion(a, []string{"id-1"}, now), "SubjectConfirmationData NotOnOrAfter within skew in the past")
}

// saml-core §2.3.3 (lines 550-558): Version, ID, IssueInstant and Issuer are
// Required on <Assertion>, and "The identifier for the version of SAML
// defined in this specification is \"2.0\"". Assertion.Element always writes
// Version="2.0", and the IdP's assertions carry all four.
func TestSpecCore_2_3_3_GeneratedAssertionRequiredAttributes(t *testing.T) {
	el := (&Assertion{ID: "id-x", IssueInstant: TimeNow(), Issuer: Issuer{Value: "https://idp.example.com/"}}).Element()
	assert.Check(t, is.Equal("2.0", el.SelectAttrValue("Version", "")))

	req := specCoreIDPRequest(t)
	assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "f00d", NameID: "n"}))
	assert.Check(t, is.Equal("2.0", req.Assertion.Version))
	el = req.Assertion.Element()
	assert.Check(t, is.Equal("2.0", el.SelectAttrValue("Version", "")))
	assert.Check(t, el.SelectAttrValue("ID", "") != "")
	assert.Check(t, el.SelectAttrValue("IssueInstant", "") != "")
	issuer := el.FindElement("./Issuer")
	assert.Assert(t, issuer != nil)
	assert.Check(t, is.Equal("https://idp.example.com/saml/metadata", issuer.Text()))
}

// saml-core §2.3.3 (lines 597-600): if an assertion is signed, "a relying
// party MUST verify that the signature is valid ... If it is invalid, then
// the relying party MUST NOT rely on the contents of the assertion." An
// assertion whose signature does not verify is rejected even when it is the
// only assertion in an unsigned Response.
func TestSpecCore_2_3_3_InvalidAssertionSignatureRejected(t *testing.T) {
	e := spcovSetup(t)
	signedAssertion := e.idpSign(t, e.assertion().Element())
	r := e.response()
	responseEl := r.Element()
	responseEl.AddChild(signedAssertion)
	buf := spcovSerialize(t, responseEl)

	_, err := e.sp.ParseXMLResponse(buf, []string{spcovRequestID}, e.sp.AcsURL)
	assert.NilError(t, err)

	tampered := []byte(strings.Replace(string(buf), "alice@example.com", "admin@example.com", 1))
	_, err = e.sp.ParseXMLResponse(tampered, []string{spcovRequestID}, e.sp.AcsURL)
	assert.Check(t, errors.Is(err, ErrInvalidSignature), "%v", err)
}

// saml-core §2.3.4 (lines 627-635): <EncryptedAssertion> carries an
// assertion in encrypted form. Once decrypted, the assertion is processed
// like a plaintext one, so its Conditions (§2.5.1.1, line 879: "An assertion
// that is determined to be Invalid ... MUST be rejected") still apply.
func TestSpecCore_2_3_4_EncryptedAssertionValidatedAfterDecryption(t *testing.T) {
	e := spcovSetup(t)
	build := func(a *Assertion) []byte {
		plaintext := spcovSerialize(t, a.Element())
		r := e.response()
		r.EncryptedAssertion = e.encryptedAssertion(t, plaintext)
		return spcovSerialize(t, e.idpSign(t, r.Element()))
	}

	got, err := e.sp.ParseXMLResponse(build(e.assertion()), []string{spcovRequestID}, e.sp.AcsURL)
	assert.NilError(t, err)
	assert.Check(t, is.Equal("alice@example.com", got.Subject.NameID.Value))

	expired := e.assertion()
	expired.Conditions.NotOnOrAfter = spcovNow.Add(-MaxClockSkew - time.Minute)
	_, err = e.sp.ParseXMLResponse(build(expired), []string{spcovRequestID}, e.sp.AcsURL)
	assert.Check(t, errors.Is(err, ErrExpired), "%v", err)
}

// saml-core §2.4.1.2 (lines 719-732): NotBefore is "A time instant before
// which the subject cannot be confirmed", NotOnOrAfter "A time instant at
// which the subject can no longer be confirmed", Recipient the location the
// assertion may be presented to and InResponseTo the request it answers.
// Each is enforced (beyond the allowed clock skew, errata E92).
func TestSpecCore_2_4_1_2_SubjectConfirmationDataConstraints(t *testing.T) {
	now := TimeNow()
	sp := requiredConditionsSP()
	scd := func(a *Assertion) *SubjectConfirmationData {
		return a.Subject.SubjectConfirmations[0].SubjectConfirmationData
	}

	a := validAssertion(now)
	scd(a).NotBefore = now.Add(MaxClockSkew + time.Minute)
	assert.Check(t, errors.Is(sp.validateAssertion(a, []string{"id-1"}, now), ErrNotYetValid))

	a = validAssertion(now)
	scd(a).NotOnOrAfter = now.Add(-MaxClockSkew - time.Minute)
	assert.Check(t, errors.Is(sp.validateAssertion(a, []string{"id-1"}, now), ErrExpired))

	a = validAssertion(now)
	scd(a).Recipient = "https://attacker.example.com/acs"
	assert.Check(t, errors.Is(sp.validateAssertion(a, []string{"id-1"}, now), ErrDestinationMismatch))

	a = validAssertion(now)
	scd(a).InResponseTo = "id-someone-elses-request"
	assert.Check(t, errors.Is(sp.validateAssertion(a, []string{"id-1"}, now), ErrRequestIDMismatch))

	// NotBefore in the past is fine (and the IdP never emits one).
	a = validAssertion(now)
	scd(a).NotBefore = now.Add(-time.Minute)
	assert.Check(t, sp.validateAssertion(a, []string{"id-1"}, now))
}

// saml-core §2.5.1.2 (lines 888-891): "If the value for either NotBefore or
// NotOnOrAfter is omitted, then it is considered unspecified. If the
// NotBefore attribute is unspecified ..., then the assertion is Valid with
// respect to conditions at any time before the time instant specified by the
// NotOnOrAfter attribute." Omitting NotBefore does not invalidate the
// conditions.
func TestSpecCore_2_5_1_2_UnspecifiedNotBeforeIsOpen(t *testing.T) {
	now := TimeNow()
	sp := requiredConditionsSP()

	a := validAssertion(now)
	a.Conditions.NotBefore = time.Time{}
	assert.Check(t, sp.validateAssertion(a, []string{"id-1"}, now))

	// Through the parser: the attribute is simply absent.
	e := spcovSetup(t)
	buf := specCoreSignedResponse(t, e, e.assertion(), func(el *etree.Element) {
		el.FindElement("./Conditions").RemoveAttr("NotBefore")
	})
	_, err := e.sp.ParseXMLResponse(buf, []string{spcovRequestID}, e.sp.AcsURL)
	assert.Check(t, err)
}

// saml-core §2.5.1.2 (lines 891-893): "If the NotOnOrAfter attribute is
// unspecified (and if all other conditions that are supplied evaluate to
// Valid), the assertion is Valid with respect to conditions from the time
// instant specified by the NotBefore attribute with no expiry." The
// assertion stays bounded by MaxIssueDelay and by the bearer
// SubjectConfirmationData NotOnOrAfter, and the replay cache is told the
// earlier of those.
func TestSpecCore_2_5_1_2_UnspecifiedNotOnOrAfterHasNoExpiry(t *testing.T) {
	now := TimeNow()
	sp := requiredConditionsSP()

	a := validAssertion(now)
	a.Conditions.NotOnOrAfter = time.Time{}
	assert.Check(t, sp.validateAssertion(a, []string{"id-1"}, now))
	// Here the issue deadline is the earliest one left.
	assert.Check(t, is.DeepEqual(now.Add(MaxIssueDelay), acceptableUntil(a)))

	// The SubjectConfirmationData NotOnOrAfter still applies.
	a.Subject.SubjectConfirmations[0].SubjectConfirmationData.NotOnOrAfter = now.Add(-MaxClockSkew - time.Minute)
	assert.Check(t, errors.Is(sp.validateAssertion(a, []string{"id-1"}, now), ErrExpired))

	// Through the parser: the attribute is simply absent.
	e := spcovSetup(t)
	buf := specCoreSignedResponse(t, e, e.assertion(), func(el *etree.Element) {
		el.FindElement("./Conditions").RemoveAttr("NotOnOrAfter")
	})
	_, err := e.sp.ParseXMLResponse(buf, []string{spcovRequestID}, e.sp.AcsURL)
	assert.Check(t, err)
}

// saml-core §2.5.1.2 (lines 886-887): NotOnOrAfter "specifies the time
// instant at which the validity interval has ended", and §2.4.1.2 (lines
// 722-723): "A time instant at which the subject can no longer be
// confirmed." The instant itself is outside the interval, so with no clock
// skew an assertion is refused exactly at NotOnOrAfter and accepted just
// before it.
func TestSpecCore_2_5_1_2_NotOnOrAfterIsExclusive(t *testing.T) {
	oldSkew := MaxClockSkew
	MaxClockSkew = 0
	t.Cleanup(func() { MaxClockSkew = oldSkew })

	now := TimeNow()
	sp := requiredConditionsSP()
	for name, edit := range map[string]func(a *Assertion, at time.Time){
		"Conditions": func(a *Assertion, at time.Time) { a.Conditions.NotOnOrAfter = at },
		"SubjectConfirmationData": func(a *Assertion, at time.Time) {
			a.Subject.SubjectConfirmations[0].SubjectConfirmationData.NotOnOrAfter = at
		},
	} {
		t.Run(name, func(t *testing.T) {
			a := validAssertion(now)
			edit(a, now)
			assert.Check(t, errors.Is(sp.validateAssertion(a, []string{"id-1"}, now), ErrExpired))

			a = validAssertion(now)
			edit(a, now.Add(time.Nanosecond))
			assert.Check(t, sp.validateAssertion(a, []string{"id-1"}, now))
		})
	}
}

// saml-core §2.5.1.2 (lines 886-887) and §2.5.1.1 rule 2 (lines 870-871,
// 879): NotBefore is when "the validity interval begins", NotOnOrAfter when
// it "has ended"; an assertion outside the interval is Invalid and "MUST be
// rejected".
func TestSpecCore_2_5_1_2_OutsideValidityIntervalRejected(t *testing.T) {
	now := TimeNow()
	sp := requiredConditionsSP()

	a := validAssertion(now)
	a.Conditions.NotBefore = now.Add(MaxClockSkew + time.Minute)
	assert.Check(t, errors.Is(sp.validateAssertion(a, []string{"id-1"}, now), ErrNotYetValid))

	a = validAssertion(now)
	a.Conditions.NotOnOrAfter = now.Add(-MaxClockSkew - time.Minute)
	assert.Check(t, errors.Is(sp.validateAssertion(a, []string{"id-1"}, now), ErrExpired))
}

// saml-core §2.5.1.5 (lines 962-963): "For the purposes of determining the
// validity of the <Conditions> element, the <OneTimeUse> is considered to
// always be valid." An assertion with <OneTimeUse> is accepted, and the
// condition is exposed so a caller that retains assertions can observe it
// (lines 953-954).
func TestSpecCore_2_5_1_5_OneTimeUseIsValidAndExposed(t *testing.T) {
	e := spcovSetup(t)
	a := e.assertion()
	a.Conditions.OneTimeUse = &OneTimeUse{}
	got, err := e.sp.ParseXMLResponse(specCoreSignedResponse(t, e, a, nil), []string{spcovRequestID}, e.sp.AcsURL)
	assert.NilError(t, err)
	assert.Check(t, got.Conditions.OneTimeUse != nil)
}

// saml-core §2.5.1.6 (lines 994-996): "For the purposes of determining the
// validity of the <Conditions> element, the <ProxyRestriction> condition is
// considered to always be valid." Even Count="0" does not invalidate the
// assertion for the relying party itself; Count and the Audiences are exposed.
func TestSpecCore_2_5_1_6_ProxyRestrictionIsValidAndExposed(t *testing.T) {
	e := spcovSetup(t)
	a := e.assertion()
	zero := 0
	a.Conditions.ProxyRestriction = &ProxyRestriction{Count: &zero, Audiences: []Audience{{Value: "https://other.example.com/"}}}
	got, err := e.sp.ParseXMLResponse(specCoreSignedResponse(t, e, a, nil), []string{spcovRequestID}, e.sp.AcsURL)
	assert.NilError(t, err)
	assert.Assert(t, got.Conditions.ProxyRestriction != nil)
	assert.Assert(t, got.Conditions.ProxyRestriction.Count != nil)
	assert.Check(t, is.Equal(0, *got.Conditions.ProxyRestriction.Count))
	assert.Check(t, is.DeepEqual([]Audience{{Value: "https://other.example.com/"}}, got.Conditions.ProxyRestriction.Audiences))
}

// saml-core §2.6.1 (lines 1015-1017): "This information MAY be ignored by
// applications without affecting either the semantics or the validity of the
// assertion." An assertion carrying <Advice> is accepted.
func TestSpecCore_2_6_1_AdviceMayBeIgnored(t *testing.T) {
	e := spcovSetup(t)
	buf := specCoreSignedResponse(t, e, e.assertion(), func(el *etree.Element) {
		conditions := el.FindElement("./Conditions")
		advice := etree.NewElement("saml:Advice")
		advice.CreateElement("saml:AssertionIDRef").SetText("id-some-other-assertion")
		el.InsertChildAt(conditions.Index()+1, advice)
	})
	got, err := e.sp.ParseXMLResponse(buf, []string{spcovRequestID}, e.sp.AcsURL)
	assert.NilError(t, err)
	assert.Check(t, is.Equal("alice@example.com", got.Subject.NameID.Value))
}

// saml-core §2.7.3.1 (lines 1193-1217): an <Attribute> has a Name, an
// optional NameFormat and FriendlyName, and any number of <AttributeValue>
// elements, each optionally typed with xsi:type (§2.7.3.1.1). All values are
// kept, in order, with their types.
func TestSpecCore_2_7_3_1_AttributeValuesPreserved(t *testing.T) {
	e := spcovSetup(t)
	a := e.assertion()
	a.AttributeStatements = []AttributeStatement{{Attributes: []Attribute{{
		FriendlyName: "eduPersonAffiliation",
		Name:         "urn:oid:1.3.6.1.4.1.5923.1.1.1.1",
		NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
		Values: []AttributeValue{
			{Type: "xs:string", Value: "member"},
			{Type: "xs:string", Value: "staff"},
			{Type: "xs:string", Value: ""},
		},
	}}}}
	got, err := e.sp.ParseXMLResponse(specCoreSignedResponse(t, e, a, nil), []string{spcovRequestID}, e.sp.AcsURL)
	assert.NilError(t, err)
	assert.Assert(t, is.Len(got.AttributeStatements, 1))
	assert.Assert(t, is.Len(got.AttributeStatements[0].Attributes, 1))
	attr := got.AttributeStatements[0].Attributes[0]
	assert.Check(t, is.Equal("urn:oid:1.3.6.1.4.1.5923.1.1.1.1", attr.Name))
	assert.Check(t, is.Equal("urn:oasis:names:tc:SAML:2.0:attrname-format:uri", attr.NameFormat))
	assert.Check(t, is.Equal("eduPersonAffiliation", attr.FriendlyName))
	assert.Assert(t, is.Len(attr.Values, 3))
	for i, want := range []string{"member", "staff", ""} {
		assert.Check(t, is.Equal(want, attr.Values[i].Value))
		assert.Check(t, is.Equal("xs:string", attr.Values[i].Type))
	}
}

// saml-core §2.7.3.1.1 (lines 1246-1247): "If a SAML attribute includes an
// empty value, such as the empty string, the corresponding <AttributeValue>
// element MUST be empty (generally this is serialized as
// <AttributeValue/>)."
func TestSpecCore_2_7_3_1_1_EmptyValueSerializedAsEmptyElement(t *testing.T) {
	el := (&AttributeValue{Type: "xs:string", Value: ""}).Element()
	assert.Check(t, is.Len(el.Child, 0))
	assert.Check(t, is.Equal("", el.Text()))
}

// saml-core §4.1.2 (lines 2774-2775): "A SAML relying party MUST NOT process
// any assertion with a major assertion version number not supported by the
// relying party." §4.1.3.3 (lines 2824-2830) ties the response version to
// the assertion version, and §3.2.2 makes Version required. The SP refuses
// an assertion or Response whose Version is not 2.0, or that has none.
func TestSpecCore_4_1_2_AssertionAndResponseVersion(t *testing.T) {
	e := spcovSetup(t)
	parse := func(t *testing.T, buf []byte) error {
		t.Helper()
		_, err := e.sp.ParseXMLResponse(buf, []string{spcovRequestID}, e.sp.AcsURL)
		return err
	}
	for _, version := range []string{"3.0", "1.1", ""} {
		t.Run("assertion Version "+version, func(t *testing.T) {
			buf := specCoreSignedResponse(t, e, e.assertion(), func(el *etree.Element) {
				el.RemoveAttr("Version")
				if version != "" {
					el.CreateAttr("Version", version)
				}
			})
			err := parse(t, buf)
			assert.Check(t, errors.Is(err, ErrUnsupported), "%v", err)
			assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), "assertion Version"))
		})
		t.Run("response Version "+version, func(t *testing.T) {
			r := e.response()
			r.Assertion = e.assertion()
			el := r.Element()
			el.RemoveAttr("Version")
			if version != "" {
				el.CreateAttr("Version", version)
			}
			err := parse(t, spcovSerialize(t, e.idpSign(t, el)))
			assert.Check(t, errors.Is(err, ErrUnsupported), "%v", err)
			assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), "response Version"))
		})
	}

	t.Run("ArtifactResponse Version", func(t *testing.T) {
		const artifactReqID = "id-artifact-request"
		el := e.artifactResponseEl(t, artifactReqID, false, nil)
		el.CreateAttr("Version", "3.0")
		_, err := e.sp.ParseXMLArtifactResponse(spcovSerialize(t, spcovSOAPEnvelope(e.idpSign(t, el))),
			[]string{spcovRequestID}, artifactReqID, e.sp.AcsURL)
		assert.Check(t, errors.Is(err, ErrUnsupported), "%v", err)
	})

	t.Run("2.0 accepted", func(t *testing.T) {
		assert.Check(t, parse(t, specCoreSignedResponse(t, e, e.assertion(), nil)))
	})
}

// saml-core §4.1.3.1 (line 2802): "A SAML responder MUST reject any request
// with a major request version number not supported by the responder", and
// §3.2.1 (lines 1467-1470): ID is required and the response's InResponseTo
// must match it. The SP refuses an IdP LogoutRequest with another Version or
// no ID, and a LogoutResponse with another Version.
func TestSpecCore_4_1_3_1_LogoutMessageVersionAndID(t *testing.T) {
	e := spcovSetup(t)
	request := func() *LogoutRequest {
		return &LogoutRequest{
			ID: "id-logout-request", Version: "2.0", IssueInstant: spcovNow,
			Destination: e.sp.SloURL.String(),
			Issuer:      &Issuer{Value: spcovIDPEntityID}, NameID: &NameID{Value: "alice@example.com"},
		}
	}
	assert.Check(t, e.sp.validateLogoutRequest(request()))

	for _, version := range []string{"3.0", "1.1", ""} {
		r := request()
		r.Version = version
		assert.Check(t, errors.Is(e.sp.validateLogoutRequest(r), ErrUnsupported), "LogoutRequest Version %q", version)

		resp := e.logoutResponse()
		resp.Version = version
		assert.Check(t, errors.Is(e.sp.validateLogoutResponse(resp), ErrUnsupported), "LogoutResponse Version %q", version)
	}

	r := request()
	r.ID = ""
	err := e.sp.validateLogoutRequest(r)
	assert.Check(t, errors.Is(err, ErrMissingElement), "%v", err)
}

// saml-core §4.1.3.1 (lines 2800-2803): "A SAML requester MUST NOT issue a
// request message with an overall Major.Minor request version number
// matching a response version number that the requester does not support"
// and "A SAML responder MUST reject any request with a major request version
// number not supported by the responder." The SP issues 2.0 requests; the
// IdP rejects requests of another major version.
func TestSpecCore_4_1_3_1_RequestVersion(t *testing.T) {
	e := spcovSetup(t)
	authnReq, err := e.sp.MakeAuthenticationRequest("https://idp.example.com/sso/post", HTTPPostBinding, HTTPPostBinding)
	assert.NilError(t, err)
	assert.Check(t, is.Equal("2.0", authnReq.Version))
	assert.Check(t, is.Equal("2.0", authnReq.Element().SelectAttrValue("Version", "")))
	logoutReq, err := e.sp.MakeLogoutRequest("https://idp.example.com/slo/post", "alice")
	assert.NilError(t, err)
	assert.Check(t, is.Equal("2.0", logoutReq.Version))

	for _, version := range []string{"1.1", "3.0", ""} {
		req := specCoreIDPRequest(t)
		req.RequestBuffer = []byte(strings.Replace(string(req.RequestBuffer), `Version="2.0"`, `Version="`+version+`"`, 1))
		err := req.Validate()
		assert.Check(t, errors.Is(err, ErrUnsupported), "Version=%q: %v", version, err)
	}
}

// saml-core §8.3 (lines 3275-3362) and errata E60 (§2.2.2, errata line 507:
// the unspecified format is urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified):
// the library's name identifier format constants are the spec's URIs.
func TestSpecCore_8_3_NameIDFormatIdentifiers(t *testing.T) {
	assert.Check(t, is.Equal(NameIDFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"), UnspecifiedNameIDFormat))
	assert.Check(t, is.Equal(NameIDFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"), EmailAddressNameIDFormat))
	assert.Check(t, is.Equal(NameIDFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"), PersistentNameIDFormat))
	assert.Check(t, is.Equal(NameIDFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:transient"), TransientNameIDFormat))
}

// saml-core §8.3.6 (entity identifier): "The NameQualifier, SPNameQualifier,
// and SPProvidedID attributes MUST be omitted." The Issuer of the IdP's
// assertions uses the entity format with none of them.
func TestSpecCore_8_3_6_IssuerEntityFormatOmitsQualifiers(t *testing.T) {
	req := specCoreIDPRequest(t)
	assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "f00d", NameID: "n"}))
	issuer := req.Assertion.Element().FindElement("./Issuer")
	assert.Assert(t, issuer != nil)
	assert.Check(t, is.Equal("urn:oasis:names:tc:SAML:2.0:nameid-format:entity", issuer.SelectAttrValue("Format", "")))
	for _, attr := range []string{"NameQualifier", "SPNameQualifier", "SPProvidedID"} {
		assert.Check(t, issuer.SelectAttr(attr) == nil, "Issuer has %s", attr)
	}
}

// saml-core §8.2.2 (URI reference attribute name format): with NameFormat
// urn:oasis:names:tc:SAML:2.0:attrname-format:uri the Name is a URI
// reference. The attributes the IdP generates in that format have absolute
// URI names (§1.3.2: URI values "are REQUIRED to be absolute").
func TestSpecCore_8_2_GeneratedURIAttributeNamesAreAbsolute(t *testing.T) {
	req := specCoreIDPRequest(t)
	assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{
		ID: "f00d", NameID: "n", UserName: "alice", UserEmail: "alice@example.com",
		UserSurname: "Smith", UserGivenName: "Alice", UserCommonName: "Alice Smith",
		UserScopedAffiliation: "member@example.com", Groups: []string{"g"}, SubjectID: "alice@example.com",
	}))
	absoluteURI := regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*:\S+$`)
	var n int
	for _, statement := range req.Assertion.AttributeStatements {
		for _, attr := range statement.Attributes {
			if attr.NameFormat != "urn:oasis:names:tc:SAML:2.0:attrname-format:uri" {
				continue
			}
			n++
			assert.Check(t, absoluteURI.MatchString(attr.Name), "attribute name %q", attr.Name)
		}
	}
	assert.Check(t, n > 0)
}
