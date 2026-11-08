package saml

import (
	"encoding/xml"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

func TestRelaxedTimeFormat(t *testing.T) {
	rt := time.Date(1981, 02, 03, 14, 15, 16, 17, time.UTC)
	assert.Check(t, is.Equal("1981-02-03T14:15:16Z", RelaxedTime(rt).String()))

	buf, err := RelaxedTime(rt).MarshalText()
	assert.Check(t, err)
	assert.Check(t, is.Equal("1981-02-03T14:15:16Z", string(buf)))

	loc, err := time.LoadLocation("America/New_York")
	assert.Check(t, err)
	rt = time.Date(1981, 02, 03, 9, 15, 16, 17, loc)

	assert.Check(t, is.Equal("1981-02-03T14:15:16Z", RelaxedTime(rt).String()))
	buf, err = RelaxedTime(rt).MarshalText()
	assert.Check(t, err)
	assert.Check(t, is.Equal("1981-02-03T14:15:16Z", string(buf)))
}

func TestRelaxedTimeParse(t *testing.T) {
	{
		var rt RelaxedTime
		err := rt.UnmarshalText([]byte("1981-02-03T14:15:16Z"))
		assert.Check(t, err)
		assert.Check(t, is.DeepEqual(
			RelaxedTime(time.Date(1981, 02, 03, 14, 15, 16, 0, time.UTC)),
			rt, cmp.AllowUnexported(RelaxedTime{})))
	}

	{
		var rt RelaxedTime
		err := rt.UnmarshalText([]byte("1981-02-03T14:15:16.178901234Z"))
		assert.Check(t, err)
		assert.Check(t, is.DeepEqual(RelaxedTime(time.Date(1981, 02, 03, 14, 15, 16, 179000000, time.UTC)),
			rt, cmp.AllowUnexported(RelaxedTime{})))
	}
	{
		var rt RelaxedTime
		err := rt.UnmarshalText([]byte("1981-02-03T14:15:16.1717Z"))
		assert.Check(t, err)
		assert.Check(t, is.DeepEqual(RelaxedTime(time.Date(1981, 02, 03, 14, 15, 16, 172000000, time.UTC)),
			rt, cmp.AllowUnexported(RelaxedTime{})))
	}
	{
		var rt RelaxedTime
		err := rt.UnmarshalText([]byte("1981-02-03T14:15:16Z04:00"))
		assert.Check(t, is.Error(err,
			"parsing time \"1981-02-03T14:15:16Z04:00\": extra text: \"04:00\""))
	}
}

// saml-core §1.3.3: SAML time values "MUST be expressed in UTC form, with
// no time zone component". A time with no zone designator names no instant
// and is refused; so is one with a numeric offset, even "+00:00".
func TestRelaxedTimeRequiresUTC(t *testing.T) {
	for _, s := range []string{
		"1981-02-03T14:15:16",
		"1981-02-03T14:15:16.123",
		"1981-02-03T14:15:16+00:00",
		"1981-02-03T14:15:16-05:00",
		"1981-02-03T14:15:16.5+01:00",
	} {
		var rt RelaxedTime
		err := rt.UnmarshalText([]byte(s))
		assert.Check(t, is.ErrorContains(err, "is not in UTC"), s)
	}

	// Through encoding/xml, as an assertion is read.
	var a Assertion
	err := xml.Unmarshal([]byte(`<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="a" Version="2.0" IssueInstant="2030-01-01T00:00:00"/>`), &a)
	assert.Check(t, is.ErrorContains(err, "is not in UTC"))
	err = xml.Unmarshal([]byte(`<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="a" Version="2.0" IssueInstant="2030-01-01T02:00:00+02:00"/>`), &a)
	assert.Check(t, is.ErrorContains(err, "is not in UTC"))
	err = xml.Unmarshal([]byte(`<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="a" Version="2.0" IssueInstant="2030-01-01T00:00:00.1234Z"/>`), &a)
	assert.Check(t, err)
	assert.Check(t, a.IssueInstant.Equal(time.Date(2030, 1, 1, 0, 0, 0, 123000000, time.UTC)))
}

// Metadata time attributes are read leniently: see metadataTime and
// TestConformanceDeviation_MetadataTimeZone.
func TestMetadataTimeLenient(t *testing.T) {
	for s, want := range map[string]time.Time{
		"2030-01-01T00:00:00Z":          time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		"2030-01-01T00:00:00.5":         time.Date(2030, 1, 1, 0, 0, 0, 500000000, time.UTC),
		"2030-01-01T02:00:00+02:00":     time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		"2029-12-31T19:00:00.000-05:00": time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
	} {
		var mt metadataTime
		assert.Check(t, mt.UnmarshalText([]byte(s)), s)
		assert.Check(t, time.Time(mt).Equal(want), s)
		out, err := mt.MarshalText()
		assert.Check(t, err)
		assert.Check(t, is.Equal(string(out), RelaxedTime(want).String()))
	}
	var mt metadataTime
	assert.Check(t, is.ErrorContains(mt.UnmarshalText([]byte("bogus")), "cannot parse"))
}
