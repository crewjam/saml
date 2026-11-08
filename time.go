package saml

import (
	"fmt"
	"time"
)

// RelaxedTime is a version of time.Time that reads and writes the time
// values of SAML protocol messages and assertions.
//
// saml-core §1.3.3 says SAML time values "MUST be expressed in UTC form,
// with no time zone component", that is as an xs:dateTime ending in "Z".
// UnmarshalText accepts only that form; a time with a numeric offset
// (even "+00:00") or with no zone designator at all is refused. A time with
// no zone does not name an instant, so reading it as UTC could move a
// validity window by hours. It is "relaxed" only in accepting fractional
// seconds of any precision, which it rounds to the millisecond.
//
// Metadata time attributes (validUntil) are read more leniently; see
// metadataTime.
type RelaxedTime time.Time

const timeFormat = "2006-01-02T15:04:05.999Z07:00"

// formatTime formats t for a SAML message. saml-core §1.3.3 says SAML time
// values "MUST be expressed in UTC form, with no time zone component", so t
// is converted to UTC first; a time in another zone would otherwise keep
// its offset. Fractions finer than a millisecond are dropped.
func formatTime(t time.Time) string {
	return t.UTC().Format(timeFormat)
}

// optionalRelaxedTime returns t as a *RelaxedTime, or nil if t is the zero
// time. It is used for optional time attributes, so that MarshalXML leaves
// out an unset time as Element does, instead of writing
// "0001-01-01T00:00:00Z" (which reads as long expired).
func optionalRelaxedTime(t time.Time) *RelaxedTime {
	if t.IsZero() {
		return nil
	}
	rt := RelaxedTime(t)
	return &rt
}

// MarshalText implements encoding.TextMarshaler
func (m RelaxedTime) MarshalText() ([]byte, error) {
	// According to section 1.2.2 of the OASIS SAML 1.1 spec, we can't trust
	// other applications to handle time resolution finer than a millisecond.
	//
	// The time MUST be expressed in UTC.
	return []byte(m.String()), nil
}

func (m RelaxedTime) String() string {
	return time.Time(m).Round(time.Millisecond).UTC().Format(timeFormat)
}

// UnmarshalText implements encoding.TextUnmarshaler. An empty value is the
// zero time; any other value must be a UTC xs:dateTime ending in "Z"
// (saml-core §1.3.3).
func (m *RelaxedTime) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		*m = RelaxedTime(time.Time{})
		return nil
	}
	s := string(text)
	// time.Parse accepts a fraction of any length after the seconds, or none.
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		if _, errNoZone := time.Parse(noZoneTimeFormat, s); errNoZone == nil {
			return notUTCError(s)
		}
		return err
	}
	if s[len(s)-1] != 'Z' {
		return notUTCError(s)
	}
	*m = RelaxedTime(t.Round(time.Millisecond))
	return nil
}

// noZoneTimeFormat is an xs:dateTime with no zone designator.
const noZoneTimeFormat = "2006-01-02T15:04:05.999999999"

func notUTCError(s string) error {
	return fmt.Errorf("time %q is not in UTC: SAML time values must end in \"Z\" (saml-core §1.3.3)", s)
}

// metadataTime is RelaxedTime for the time attributes of metadata
// (validUntil, saml-metadata §2.2.1 and following). It is written like
// RelaxedTime, in UTC, but read leniently: a time with a numeric offset is
// converted to UTC, and a time with no zone designator is read as UTC.
//
// This departs from saml-core §1.3.3, which requires "Z", because metadata
// is published by many parties, often by hand or with generators that write
// no zone (testdata/TestCanParseMetadata_metadata.xml is such a document),
// and refusing it would make the whole document unreadable. The cost is
// small: a validUntil without a zone may be read some hours off, which only
// moves when the metadata is treated as expired. TestConformanceDeviation_
// MetadataTimeZone pins this.
type metadataTime time.Time

// MarshalText implements encoding.TextMarshaler, as RelaxedTime does.
func (m metadataTime) MarshalText() ([]byte, error) {
	return RelaxedTime(m).MarshalText()
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (m *metadataTime) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		*m = metadataTime(time.Time{})
		return nil
	}
	t, err1 := time.Parse(time.RFC3339, string(text))
	if err1 == nil {
		*m = metadataTime(t.Round(time.Millisecond))
		return nil
	}
	t, err2 := time.Parse(noZoneTimeFormat, string(text))
	if err2 == nil {
		*m = metadataTime(t.Round(time.Millisecond))
		return nil
	}
	return err1
}
