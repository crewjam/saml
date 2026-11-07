package saml

import (
	"encoding/xml"
	"fmt"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// conditionsWithAudiences returns a Conditions element whose one
// AudienceRestriction lists audiences in order. An audience written
// "x|value" is put in a foreign namespace instead of the SAML one.
func conditionsWithAudiences(audiences ...string) string {
	var b strings.Builder
	b.WriteString(`<saml:Conditions xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:x="urn:example:foreign"><saml:AudienceRestriction>`)
	for _, a := range audiences {
		prefix, value, ok := strings.Cut(a, "|")
		if !ok {
			prefix, value = "saml", a
		}
		fmt.Fprintf(&b, "<%s:Audience>%s</%s:Audience>", prefix, value, prefix)
	}
	b.WriteString(`</saml:AudienceRestriction></saml:Conditions>`)
	return b.String()
}

// An AudienceRestriction may list several audiences (saml-core §2.5.1.4).
// All of them are read, and the assertion is for this service provider when
// any one of them names it.
func TestAudienceRestrictionWithMultipleAudiences(t *testing.T) {
	const ours = "https://sp.example.com/metadata"
	const other1 = "https://other1.example.com/"
	const other2 = "https://other2.example.com/"

	cases := []struct {
		name      string
		audiences []string
		err       string
	}{
		{name: "only", audiences: []string{ours}},
		{name: "first", audiences: []string{ours, other1, other2}},
		{name: "middle", audiences: []string{other1, ours, other2}},
		{name: "last", audiences: []string{other1, other2, ours}},
		{
			name:      "absent",
			audiences: []string{other1, other2},
			err:       `assertion Conditions AudienceRestriction does not contain "https://sp.example.com/metadata"`,
		},
		{
			// An Audience outside the SAML assertion namespace is not part
			// of the restriction.
			name:      "foreign namespace",
			audiences: []string{"x|" + ours, other1},
			err:       `assertion Conditions AudienceRestriction does not contain "https://sp.example.com/metadata"`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			now := TimeNow()
			sp := requiredConditionsSP()
			a := validAssertion(now)
			conditions := &Conditions{}
			assert.NilError(t, xml.Unmarshal([]byte(conditionsWithAudiences(c.audiences...)), conditions))
			a.Conditions.AudienceRestrictions = conditions.AudienceRestrictions

			err := sp.validateAssertion(a, []string{"id-1"}, now)
			if c.err == "" {
				assert.Check(t, err)
			} else {
				assert.Check(t, is.Error(err, c.err))
			}
		})
	}
}

func TestAudienceRestrictionUnmarshalKeepsAllAudiences(t *testing.T) {
	var c Conditions
	assert.NilError(t, xml.Unmarshal([]byte(conditionsWithAudiences("a", "x|foreign", "b", "c")), &c))
	assert.Assert(t, is.Len(c.AudienceRestrictions, 1))
	ar := c.AudienceRestrictions[0]
	assert.Check(t, is.DeepEqual(Audience{Value: "a"}, ar.Audience))
	assert.Check(t, is.DeepEqual([]Audience{{Value: "b"}, {Value: "c"}}, ar.AdditionalAudiences))
	assert.Check(t, is.DeepEqual([]Audience{{Value: "a"}, {Value: "b"}, {Value: "c"}}, ar.AllAudiences()))

	// A single Audience leaves AdditionalAudiences nil, so the result equals
	// an AudienceRestriction built with only Audience.
	c = Conditions{}
	assert.NilError(t, xml.Unmarshal([]byte(conditionsWithAudiences("a")), &c))
	assert.Check(t, is.DeepEqual([]AudienceRestriction{{Audience: Audience{Value: "a"}}}, c.AudienceRestrictions))
}

func TestAudienceRestrictionMarshal(t *testing.T) {
	// Built with only Audience, the XML is what it always was.
	single := &AudienceRestriction{Audience: Audience{Value: "a"}}
	buf, err := xml.Marshal(single)
	assert.NilError(t, err)
	assert.Check(t, is.Equal(
		`<AudienceRestriction><Audience xmlns="urn:oasis:names:tc:SAML:2.0:assertion">a</Audience></AudienceRestriction>`,
		string(buf)))
	assert.Check(t, is.Equal(
		`<saml:AudienceRestriction><saml:Audience>a</saml:Audience></saml:AudienceRestriction>`,
		elementString(t, single.Element())))

	multiple := &AudienceRestriction{
		Audience:            Audience{Value: "a"},
		AdditionalAudiences: []Audience{{Value: "b"}, {Value: "c"}},
	}
	assert.Check(t, is.Equal(
		`<saml:AudienceRestriction><saml:Audience>a</saml:Audience><saml:Audience>b</saml:Audience><saml:Audience>c</saml:Audience></saml:AudienceRestriction>`,
		elementString(t, multiple.Element())))

	// encoding/xml round trips every audience.
	buf, err = xml.Marshal(&Conditions{AudienceRestrictions: []AudienceRestriction{*multiple}})
	assert.NilError(t, err)
	var c Conditions
	assert.NilError(t, xml.Unmarshal(buf, &c))
	assert.Check(t, is.DeepEqual([]AudienceRestriction{*multiple}, c.AudienceRestrictions))
}

func elementString(t *testing.T, el *etree.Element) string {
	t.Helper()
	doc := etree.NewDocument()
	doc.SetRoot(el)
	s, err := doc.WriteToString()
	assert.NilError(t, err)
	return s
}
