package samlsp

import (
	"encoding"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/crewjam/saml"
)

// DecodeAttributes stores the assertion's attributes in the struct that v
// points to. Each field to set has a tag with the Name of its attribute
// (not its FriendlyName, which does not identify it):
//
//	var user struct {
//		Email    string    `saml:"urn:oid:0.9.2342.19200300.100.1.3"`
//		Groups   []string  `saml:"http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"`
//		Verified bool      `saml:"https://example.com/claims/email_verified"`
//		Hired    time.Time `saml:"urn:oid:2.16.840.1.113730.3.1.999"`
//	}
//	err := assertion.DecodeAttributes(&user)
//
// A value is parsed from its text by the type of the field, using the
// lexical rules of the XML Schema type that corresponds to it
// (saml-core §2.7.3.1.1; XML Schema Part 2 §3.2-3.3):
//
//	string                  xs:string, unchanged
//	bool                    xs:boolean: "true", "false", "1" or "0"
//	int, int8 ... int64     xs:integer, in range for the field
//	uint, uint8 ... uint64  xs:nonNegativeInteger, in range for the field
//	float32, float64        xs:double, including "INF", "-INF" and "NaN"
//	time.Time               xs:dateTime; without a time zone, UTC
//	time.Duration           xs:duration, such as "PT1H30M"
//	[]byte                  xs:base64Binary
//	url.URL, *url.URL       xs:anyURI
//
// A field whose type implements AttributeUnmarshaler is given the whole
// attribute instead, which takes precedence over everything else; a field
// of type Attribute receives the attribute as it is. A field of any other
// type that implements encoding.TextUnmarshaler, through a pointer, is
// given the text. The declared type of a value
// (xsi:type, see Attribute.Types) is not consulted, because many IdPs send
// every value as an untyped string.
//
// A field that is a slice of one of these types (other than []byte, which
// is one value) receives all the values of its attribute; any other field
// receives the first. A pointer field is allocated, so a *bool or a
// *time.Time tells an absent attribute from a zero value. A field whose
// attribute is absent, or has only null values, is left unchanged.
//
// DecodeAttributes returns an error, naming the attribute and the field,
// if a value cannot be parsed or a field has a type it cannot fill.
// Fields set before the error keep their new values.
func (a *Assertion) DecodeAttributes(v any) error {
	return a.Attributes.Decode(v)
}

// Decode stores the attributes in the struct that v points to, as
// Assertion.DecodeAttributes does. Use it for the attributes that
// QueryAttributes returns.
func (as Attributes) Decode(v any) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() || rv.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("samlsp: DecodeAttributes needs a non-nil pointer to a struct, not %T", v)
	}
	rv = rv.Elem()
	rt := rv.Type()
	for i := range rt.NumField() {
		f := rt.Field(i)
		name, ok := f.Tag.Lookup("saml")
		if !ok || name == "" || name == "-" || !f.IsExported() {
			continue
		}
		attr, ok := as.lookup(name)
		if !ok {
			continue
		}
		if err := decodeField(rv.Field(i), attr); err != nil {
			return fmt.Errorf("samlsp: DecodeAttributes: attribute %q into field %s (%s): %w", name, f.Name, f.Type, err)
		}
	}
	return nil
}

// AttributeUnmarshaler is implemented by types that decode themselves from
// a SAML attribute. DecodeAttributes prefers it to encoding.TextUnmarshaler
// and to its own parsing.
//
// A field whose type implements it (through a pointer) is given the whole
// attribute: every value, with its declared type in Types. A field that is
// a slice of such a type has each element given the attribute with one of
// its values. It is not called for an attribute that is absent or has only
// null values.
type AttributeUnmarshaler interface {
	UnmarshalSAMLAttribute(attr Attribute) error
}

// UnmarshalSAMLAttribute implements AttributeUnmarshaler: a field of type
// Attribute receives the attribute as it is.
func (a *Attribute) UnmarshalSAMLAttribute(attr Attribute) error {
	*a = attr
	return nil
}

// lookup returns the attribute whose Name is name, with the values of every
// such attribute in the assertion, or false if there are none.
func (as Attributes) lookup(name string) (Attribute, bool) {
	var out Attribute
	found := false
	for _, a := range as {
		if a.Name != name {
			continue
		}
		if !found {
			out = Attribute{Name: a.Name, NameFormat: a.NameFormat, FriendlyName: a.FriendlyName}
			found = true
		}
		for i, v := range a.Values {
			out.Values = append(out.Values, v)
			out.Types = append(out.Types, typeAt(a, i))
		}
	}
	return out, found && len(out.Values) > 0
}

// typeAt returns the declared type of the i-th value of a, or "".
func typeAt(a Attribute, i int) string {
	if i < len(a.Types) {
		return a.Types[i]
	}
	return ""
}

// one returns a with only its i-th value.
func (a Attribute) one(i int) Attribute {
	a.Values = []string{a.Values[i]}
	a.Types = []string{typeAt(a, i)}
	return a
}

var (
	attributeUnmarshalerType = reflect.TypeFor[AttributeUnmarshaler]()
	textUnmarshalerType      = reflect.TypeFor[encoding.TextUnmarshaler]()
	timeType                 = reflect.TypeFor[time.Time]()
	durationType             = reflect.TypeFor[time.Duration]()
	urlType                  = reflect.TypeFor[url.URL]()
	bytesType                = reflect.TypeFor[[]byte]()
)

// decodeField sets field from attr: the whole attribute for an
// AttributeUnmarshaler, every value for a slice (other than []byte), and
// the first value otherwise.
func decodeField(field reflect.Value, attr Attribute) error {
	t := field.Type()
	if unmarshalsAttribute(t) {
		return decodeValue(field, attr)
	}
	if t.Kind() == reflect.Slice && !isScalar(t) {
		n := len(attr.Values)
		s := reflect.MakeSlice(t, n, n)
		for i := range n {
			if err := decodeValue(s.Index(i), attr.one(i)); err != nil {
				if n > 1 {
					return fmt.Errorf("value %d: %w", i+1, err)
				}
				return err
			}
		}
		field.Set(s)
		return nil
	}
	return decodeValue(field, attr.one(0))
}

// unmarshalsAttribute reports whether a value of type t, or what it points
// to, implements AttributeUnmarshaler.
func unmarshalsAttribute(t reflect.Type) bool {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return reflect.PointerTo(t).Implements(attributeUnmarshalerType)
}

// isScalar reports whether a value of type t is decoded from one value as a
// whole, even if t is a slice.
func isScalar(t reflect.Type) bool {
	return t == bytesType || reflect.PointerTo(t).Implements(textUnmarshalerType)
}

// decodeValue sets v from attr, which has a single value unless v is an
// AttributeUnmarshaler given the whole attribute.
func decodeValue(v reflect.Value, attr Attribute) error {
	t := v.Type()
	if t.Kind() == reflect.Pointer {
		p := reflect.New(t.Elem())
		if err := decodeValue(p.Elem(), attr); err != nil {
			return err
		}
		v.Set(p)
		return nil
	}
	if u, ok := v.Addr().Interface().(AttributeUnmarshaler); ok {
		return u.UnmarshalSAMLAttribute(attr)
	}
	s := attr.Values[0]

	// Types with a lexical form of their own, before TextUnmarshaler: the
	// UnmarshalText of time.Time is RFC 3339, not xs:dateTime.
	switch t {
	case timeType:
		tm, err := parseDateTime(collapse(s))
		if err != nil {
			return err
		}
		v.Set(reflect.ValueOf(tm))
		return nil
	case durationType:
		var d saml.Duration
		if err := d.UnmarshalText([]byte(collapse(s))); err != nil {
			return fmt.Errorf("invalid xs:duration %q: %w", s, err)
		}
		v.SetInt(int64(d))
		return nil
	case urlType:
		u, err := url.Parse(collapse(s))
		if err != nil {
			return fmt.Errorf("invalid xs:anyURI: %w", err)
		}
		v.Set(reflect.ValueOf(*u))
		return nil
	case bytesType:
		b, err := base64.StdEncoding.DecodeString(strings.Map(dropXMLSpace, s))
		if err != nil {
			return fmt.Errorf("invalid xs:base64Binary: %w", err)
		}
		v.SetBytes(b)
		return nil
	}
	if u, ok := v.Addr().Interface().(encoding.TextUnmarshaler); ok {
		return u.UnmarshalText([]byte(s))
	}

	switch t.Kind() {
	case reflect.String:
		v.SetString(s) // xs:string keeps its whitespace
		return nil
	case reflect.Bool:
		switch collapse(s) {
		case "true", "1":
			v.SetBool(true)
		case "false", "0":
			v.SetBool(false)
		default:
			return fmt.Errorf("invalid xs:boolean %q", s)
		}
		return nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		c := collapse(s)
		if !integerRE.MatchString(c) {
			return fmt.Errorf("invalid xs:integer %q", s)
		}
		n, err := strconv.ParseInt(c, 10, t.Bits())
		if err != nil {
			return fmt.Errorf("xs:integer %q is out of range", s)
		}
		v.SetInt(n)
		return nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		c := collapse(s)
		if !integerRE.MatchString(c) {
			return fmt.Errorf("invalid xs:nonNegativeInteger %q", s)
		}
		c = strings.TrimPrefix(c, "+")
		if strings.HasPrefix(c, "-") {
			if strings.Trim(c[1:], "0") != "" {
				return fmt.Errorf("xs:nonNegativeInteger %q is negative", s)
			}
			c = "0" // "-0" is a valid xs:nonNegativeInteger
		}
		n, err := strconv.ParseUint(c, 10, t.Bits())
		if err != nil {
			return fmt.Errorf("xs:nonNegativeInteger %q is out of range", s)
		}
		v.SetUint(n)
		return nil
	case reflect.Float32, reflect.Float64:
		f, err := parseDouble(collapse(s), t.Bits())
		if err != nil {
			return fmt.Errorf("invalid xs:double %q", s)
		}
		v.SetFloat(f)
		return nil
	}
	return errors.New("unsupported field type")
}

// collapse applies the whiteSpace="collapse" facet that XML Schema gives
// every simple type but xs:string: leading and trailing whitespace go, and
// inner runs become one space.
func collapse(s string) string {
	return strings.Join(strings.FieldsFunc(s, isXMLSpace), " ")
}

func isXMLSpace(r rune) bool { return r == ' ' || r == '\t' || r == '\n' || r == '\r' }

func dropXMLSpace(r rune) rune {
	if isXMLSpace(r) {
		return -1
	}
	return r
}

var (
	// integerRE is the lexical space of xs:integer.
	integerRE = regexp.MustCompile(`^[+-]?[0-9]+$`)

	// doubleRE is the lexical space of the finite values of xs:double.
	doubleRE = regexp.MustCompile(`^[+-]?([0-9]+(\.[0-9]*)?|\.[0-9]+)([eE][+-]?[0-9]+)?$`)

	// dateTimeRE is the lexical space of xs:dateTime: a four-digit (or
	// longer) year, optional fractional seconds and an optional time zone.
	dateTimeRE = regexp.MustCompile(`^(-?[0-9]{4,})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})?$`)
)

// parseDouble parses s, an xs:double, into a float of bitSize bits.
func parseDouble(s string, bitSize int) (float64, error) {
	switch s {
	case "INF", "+INF":
		return math.Inf(1), nil
	case "-INF":
		return math.Inf(-1), nil
	case "NaN":
		return math.NaN(), nil
	}
	if !doubleRE.MatchString(s) {
		return 0, errors.New("invalid")
	}
	return strconv.ParseFloat(s, bitSize)
}

// parseDateTime parses s, an xs:dateTime. A value without a time zone has
// none in XML Schema; it is read as UTC, which is what SAML uses for its
// own times (saml-core §1.3.3).
func parseDateTime(s string) (time.Time, error) {
	m := dateTimeRE.FindStringSubmatch(s)
	if m == nil {
		return time.Time{}, fmt.Errorf("invalid xs:dateTime %q", s)
	}
	if strings.HasPrefix(m[1], "-") || len(m[1]) > 4 {
		return time.Time{}, fmt.Errorf("xs:dateTime %q has a year outside 0000-9999", s)
	}
	if m[4] == "24" {
		// 24:00:00 is the first instant of the next day.
		if m[5] != "00" || m[6] != "00" || strings.Trim(m[7], ".0") != "" {
			return time.Time{}, fmt.Errorf("invalid xs:dateTime %q", s)
		}
		t, err := parseDateTime(m[1] + "-" + m[2] + "-" + m[3] + "T00:00:00" + m[8])
		return t.AddDate(0, 0, 1), err
	}
	layout := "2006-01-02T15:04:05.999999999"
	value := s
	if m[8] == "" {
		value += "Z"
	}
	t, err := time.Parse(layout+"Z07:00", value)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid xs:dateTime %q", s)
	}
	return t, nil
}
