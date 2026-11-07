package saml

// Tests for saml-core §2.5.1.1 (lines 872-881): a <Conditions> element with
// a condition the relying party does not understand makes the assertion
// Indeterminate, and an Indeterminate assertion MUST be rejected.

import (
	"encoding/xml"
	"errors"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

const conditionsUnknownErr = "assertion Conditions has unrecognised conditions"

// conditionsUnknownMutations add one child to the Conditions of an
// Assertion element. unknown is the name it is recorded under, or the zero
// Name if the child is a condition this package understands.
var conditionsUnknownMutations = []struct {
	name    string
	unknown xml.Name
	mutate  func(conditionsEl *etree.Element)
}{
	{"xsi:typed saml:Condition", xml.Name{Space: "urn:oasis:names:tc:SAML:2.0:assertion", Local: "Condition"},
		func(c *etree.Element) {
			el := c.CreateElement("saml:Condition")
			el.CreateAttr("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
			el.CreateAttr("xmlns:ext", "urn:example:conditions")
			el.CreateAttr("xsi:type", "ext:MustBeOnTuesday")
		}},
	{"foreign namespace child", xml.Name{Space: "urn:example:conditions", Local: "MustBeOnTuesday"},
		func(c *etree.Element) {
			el := c.CreateElement("ext:MustBeOnTuesday")
			el.CreateAttr("xmlns:ext", "urn:example:conditions")
		}},
	{"unknown child in the SAML namespace", xml.Name{Space: "urn:oasis:names:tc:SAML:2.0:assertion", Local: "MustBeOnTuesday"},
		func(c *etree.Element) { c.CreateElement("saml:MustBeOnTuesday") }},
	{"OneTimeUse", xml.Name{}, func(c *etree.Element) { c.CreateElement("saml:OneTimeUse") }},
	{"ProxyRestriction", xml.Name{}, func(c *etree.Element) {
		pr := c.CreateElement("saml:ProxyRestriction")
		pr.CreateAttr("Count", "1")
		pr.CreateElement("saml:Audience").SetText("https://other-sp.example.com/")
	}},
	{"second AudienceRestriction", xml.Name{}, func(c *etree.Element) {
		ar := c.CreateElement("saml:AudienceRestriction")
		ar.CreateElement("saml:Audience").SetText("https://sp.example.com/saml/metadata")
	}},
}

func conditionsUnknownMutate(t *testing.T, mutate func(*etree.Element)) func(*etree.Element) {
	return func(assertionEl *etree.Element) {
		c := assertionEl.FindElement("./Conditions")
		assert.Assert(t, c != nil)
		mutate(c)
	}
}

func TestConditionsUnmarshalRecordsUnknownConditions(t *testing.T) {
	for _, tc := range conditionsUnknownMutations {
		t.Run(tc.name, func(t *testing.T) {
			el := (&Conditions{}).Element()
			el.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
			tc.mutate(el)
			var c Conditions
			assert.NilError(t, unmarshalElement(el, &c))
			if tc.unknown == (xml.Name{}) {
				assert.Check(t, is.Len(c.UnknownConditions, 0))
			} else {
				assert.Check(t, is.DeepEqual(c.UnknownConditions, []xml.Name{tc.unknown}))
			}
		})
	}
}

func TestParseXMLResponseUnknownConditions(t *testing.T) {
	for _, tc := range conditionsUnknownMutations {
		t.Run(tc.name, func(t *testing.T) {
			e := spcovSetup(t)
			buf := specCoreSignedResponse(t, e, e.assertion(), conditionsUnknownMutate(t, tc.mutate))
			assertion, err := e.sp.ParseXMLResponse(buf, []string{spcovRequestID}, e.sp.AcsURL)
			if tc.unknown == (xml.Name{}) {
				assert.NilError(t, err)
				return
			}
			assert.Check(t, assertion == nil)
			assert.Check(t, errors.Is(err, ErrUnsupported), "%v", err)
			var ire *InvalidResponseError
			assert.Assert(t, errors.As(err, &ire))
			assert.Check(t, is.ErrorContains(ire.PrivateErr, conditionsUnknownErr))
			assert.Check(t, is.ErrorContains(ire.PrivateErr, "{"+tc.unknown.Space+"}"+tc.unknown.Local))
		})
	}
}

func TestParseXMLResponseValidateUnknownConditions(t *testing.T) {
	e := spcovSetup(t)
	buf := specCoreSignedResponse(t, e, e.assertion(), conditionsUnknownMutate(t, conditionsUnknownMutations[0].mutate))

	var seen []xml.Name
	e.sp.ValidateUnknownConditions = func(a *Assertion) error {
		seen = a.Conditions.UnknownConditions
		return nil
	}
	assertion, err := e.sp.ParseXMLResponse(buf, []string{spcovRequestID}, e.sp.AcsURL)
	assert.NilError(t, err)
	assert.Check(t, assertion != nil)
	assert.Check(t, is.DeepEqual(seen, []xml.Name{conditionsUnknownMutations[0].unknown}))

	hookErr := errors.New("not on a Tuesday")
	e.sp.ValidateUnknownConditions = func(*Assertion) error { return hookErr }
	_, err = e.sp.ParseXMLResponse(buf, []string{spcovRequestID}, e.sp.AcsURL)
	assert.Check(t, errors.Is(err, hookErr), "%v", err)
}

// The hook is not consulted when every condition is understood.
func TestValidateUnknownConditionsNotCalledWithoutUnknownConditions(t *testing.T) {
	e := spcovSetup(t)
	e.sp.ValidateUnknownConditions = func(*Assertion) error { return errors.New("called") }
	buf := specCoreSignedResponse(t, e, e.assertion(), nil)
	_, err := e.sp.ParseXMLResponse(buf, []string{spcovRequestID}, e.sp.AcsURL)
	assert.NilError(t, err)
}

// conditionsUnknownAttributeQueryResponse is the SOAP envelope of a signed
// attribute query Response whose Assertion element is changed by mutate.
func conditionsUnknownAttributeQueryResponse(t *testing.T, e *spcovEnv, query *AttributeQuery, mutate func(*etree.Element)) []byte {
	t.Helper()
	el := e.aqResponseEl(t, query, aqOptions{})
	assertionEl := el.FindElement("./Assertion")
	assert.Assert(t, assertionEl != nil)
	conditionsUnknownMutate(t, mutate)(assertionEl)
	return spcovSerialize(t, spcovSOAPEnvelope(e.idpSign(t, el)))
}

func TestParseXMLAttributeQueryResponseUnknownConditions(t *testing.T) {
	for _, tc := range conditionsUnknownMutations {
		t.Run(tc.name, func(t *testing.T) {
			e := aqSetup(t)
			query := e.aqQuery(t)
			buf := conditionsUnknownAttributeQueryResponse(t, e, query, tc.mutate)
			result, err := e.sp.ParseXMLAttributeQueryResponse(buf, query)
			if tc.unknown == (xml.Name{}) {
				assert.NilError(t, err)
				assert.Check(t, is.Len(result.Assertions, 1))
				return
			}
			assert.Check(t, result == nil)
			assert.Check(t, errors.Is(err, ErrUnsupported), "%v", err)
			var ire *InvalidResponseError
			assert.Assert(t, errors.As(err, &ire))
			assert.Check(t, is.ErrorContains(ire.PrivateErr, conditionsUnknownErr))
		})
	}
}

func TestParseXMLAttributeQueryResponseValidateUnknownConditions(t *testing.T) {
	e := aqSetup(t)
	query := e.aqQuery(t)
	buf := conditionsUnknownAttributeQueryResponse(t, e, query, conditionsUnknownMutations[1].mutate)
	e.sp.ValidateUnknownConditions = func(*Assertion) error { return nil }
	result, err := e.sp.ParseXMLAttributeQueryResponse(buf, query)
	assert.NilError(t, err)
	assert.Check(t, is.Len(result.Assertions, 1))
}
