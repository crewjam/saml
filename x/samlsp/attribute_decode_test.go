package samlsp_test

import (
	"encoding/xml"
	"errors"
	"math"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml/x/samlsp"
)

// role is a named string type, which decodes like a string.
type role string

// level is a TextUnmarshaler.
type level int

func (l *level) UnmarshalText(text []byte) error {
	switch string(text) {
	case "low":
		*l = 1
	case "high":
		*l = 2
	default:
		return &url.Error{Op: "level", Err: nil}
	}
	return nil
}

func assertionWith(attrs ...samlsp.Attribute) *samlsp.Assertion {
	return &samlsp.Assertion{Attributes: attrs}
}

func attr(name string, values ...string) samlsp.Attribute {
	return samlsp.Attribute{Name: name, Values: values}
}

func TestDecodeAttributesTypes(t *testing.T) {
	a := assertionWith(
		attr("s", "  keeps spaces  "),
		attr("ss", "a", "b"),
		attr("role", "admin"),
		attr("b1", "true"), attr("b2", " 0 "), attr("bs", "1", "false"),
		attr("i", "-42"), attr("i8", "+127"), attr("u", "+0042"), attr("u0", "-0"), attr("is", "1", "2", "3"),
		attr("f", "1.5e3"), attr("finf", "-INF"), attr("fnan", "NaN"), attr("f32", ".25"),
		attr("t", "2026-03-04T05:06:07.123456Z"), attr("tlong", "2026-03-04T05:06:07.1234567891Z"), attr("tz", "2026-03-04T05:06:07+02:00"),
		attr("tlocal", "2026-03-04T05:06:07"), attr("t24", "2026-12-31T24:00:00Z"),
		attr("d", "PT1H30M"),
		attr("bytes", "aGVs\n bG8="), attr("bytess", "aGk=", "eW8="),
		attr("u1", " https://example.com/a?b=c "), attr("u2", "urn:example:x"),
		attr("ip", "192.0.2.1"), attr("ips", "192.0.2.1", "2001:db8::1"),
		attr("lvl", "high"),
		attr("pb", "false"), attr("pt", "2026-01-01T00:00:00Z"),
	)

	var got struct {
		S      string         `saml:"s"`
		SS     []string       `saml:"ss"`
		Role   role           `saml:"role"`
		B1     bool           `saml:"b1"`
		B2     bool           `saml:"b2"`
		BS     []bool         `saml:"bs"`
		I      int            `saml:"i"`
		I8     int8           `saml:"i8"`
		U      uint16         `saml:"u"`
		U0     uint           `saml:"u0"`
		IS     []int64        `saml:"is"`
		F      float64        `saml:"f"`
		FInf   float64        `saml:"finf"`
		FNaN   float64        `saml:"fnan"`
		F32    float32        `saml:"f32"`
		T      time.Time      `saml:"t"`
		TLong  time.Time      `saml:"tlong"`
		TZ     time.Time      `saml:"tz"`
		TLocal time.Time      `saml:"tlocal"`
		T24    time.Time      `saml:"t24"`
		D      time.Duration  `saml:"d"`
		Bytes  []byte         `saml:"bytes"`
		Bytess [][]byte       `saml:"bytess"`
		U1     *url.URL       `saml:"u1"`
		U2     url.URL        `saml:"u2"`
		IP     netip.Addr     `saml:"ip"`
		IPs    []netip.Addr   `saml:"ips"`
		Lvl    level          `saml:"lvl"`
		PB     *bool          `saml:"pb"`
		PT     *time.Time     `saml:"pt"`
		PAbs   *bool          `saml:"absent"`
		Kept   string         `saml:"absent"`
		Skip   map[string]int `saml:"-"`
	}
	got.Kept = "unchanged"
	if err := a.DecodeAttributes(&got); err != nil {
		t.Fatal(err)
	}

	check := func(name string, ok bool) {
		t.Helper()
		if !ok {
			t.Errorf("%s: got %+v", name, got)
		}
	}
	check("S", got.S == "  keeps spaces  ")
	check("SS", strings.Join(got.SS, ",") == "a,b")
	check("Role", got.Role == "admin")
	check("B1", got.B1)
	check("B2", !got.B2)
	check("BS", len(got.BS) == 2 && got.BS[0] && !got.BS[1])
	check("I", got.I == -42)
	check("I8", got.I8 == 127)
	check("U", got.U == 42)
	check("U0", got.U0 == 0)
	check("IS", len(got.IS) == 3 && got.IS[2] == 3)
	check("F", got.F == 1500)
	check("FInf", math.IsInf(got.FInf, -1))
	check("FNaN", math.IsNaN(got.FNaN))
	check("F32", got.F32 == 0.25)
	check("T", got.T.Equal(time.Date(2026, 3, 4, 5, 6, 7, 123456000, time.UTC)))
	check("TLong", got.TLong.Equal(time.Date(2026, 3, 4, 5, 6, 7, 123456789, time.UTC)))
	check("TZ", got.TZ.Equal(time.Date(2026, 3, 4, 3, 6, 7, 0, time.UTC)))
	check("TLocal", got.TLocal.Equal(time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)))
	check("T24", got.T24.Equal(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)))
	check("D", got.D == 90*time.Minute)
	check("Bytes", string(got.Bytes) == "hello")
	check("Bytess", len(got.Bytess) == 2 && string(got.Bytess[1]) == "yo")
	check("U1", got.U1 != nil && got.U1.Host == "example.com" && got.U1.RawQuery == "b=c")
	check("U2", got.U2.Scheme == "urn" && got.U2.Opaque == "example:x")
	check("IP", got.IP == netip.MustParseAddr("192.0.2.1"))
	check("IPs", len(got.IPs) == 2 && got.IPs[1].Is6())
	check("Lvl", got.Lvl == 2)
	check("PB", got.PB != nil && !*got.PB)
	check("PT", got.PT != nil && got.PT.Year() == 2026)
	check("PAbs", got.PAbs == nil)
	check("Kept", got.Kept == "unchanged")
}

func TestDecodeAttributesErrors(t *testing.T) {
	for _, tt := range []struct {
		value string
		field any
		want  string
	}{
		{"yes", new(struct {
			X bool `saml:"x"`
		}), "invalid xs:boolean"},
		{"True", new(struct {
			X bool `saml:"x"`
		}), "invalid xs:boolean"},
		{"0x10", new(struct {
			X int `saml:"x"`
		}), "invalid xs:integer"},
		{"1_000", new(struct {
			X int `saml:"x"`
		}), "invalid xs:integer"},
		{"128", new(struct {
			X int8 `saml:"x"`
		}), "out of range"},
		{"-1", new(struct {
			X uint `saml:"x"`
		}), "negative"},
		{"Infinity", new(struct {
			X float64 `saml:"x"`
		}), "invalid xs:double"},
		{"0x1p-2", new(struct {
			X float64 `saml:"x"`
		}), "invalid xs:double"},
		{"2026-03-04", new(struct {
			X time.Time `saml:"x"`
		}), "invalid xs:dateTime"},
		{"2026-03-04 05:06:07Z", new(struct {
			X time.Time `saml:"x"`
		}), "invalid xs:dateTime"},
		{"2026-02-30T00:00:00Z", new(struct {
			X time.Time `saml:"x"`
		}), "invalid xs:dateTime"},
		{"2026-03-04T24:00:01Z", new(struct {
			X time.Time `saml:"x"`
		}), "invalid xs:dateTime"},
		{"12345-03-04T00:00:00Z", new(struct {
			X time.Time `saml:"x"`
		}), "outside 0000-9999"},
		{"90 minutes", new(struct {
			X time.Duration `saml:"x"`
		}), "invalid xs:duration"},
		{"not base64!", new(struct {
			X []byte `saml:"x"`
		}), "invalid xs:base64Binary"},
		{"medium", new(struct {
			X level `saml:"x"`
		}), "level"},
		{"1", new(struct {
			X map[string]int `saml:"x"`
		}), "unsupported field type"},
	} {
		err := assertionWith(attr("x", tt.value)).DecodeAttributes(tt.field)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%q into %T: err = %v, want %q", tt.value, tt.field, err, tt.want)
			continue
		}
		if !strings.Contains(err.Error(), `attribute "x" into field X`) {
			t.Errorf("error does not name the attribute and field: %v", err)
		}
	}

	// A bad value in a slice is named by its position.
	var s struct {
		X []int `saml:"x"`
	}
	err := assertionWith(attr("x", "1", "two")).DecodeAttributes(&s)
	if err == nil || !strings.Contains(err.Error(), "value 2") {
		t.Errorf("err = %v", err)
	}

	for _, bad := range []any{nil, struct{}{}, new(int), (*struct{})(nil)} {
		if err := assertionWith().DecodeAttributes(bad); err == nil {
			t.Errorf("DecodeAttributes(%T) succeeded", bad)
		}
	}
}

// both implements AttributeUnmarshaler and encoding.TextUnmarshaler.
type both string

func (b *both) UnmarshalSAMLAttribute(attr samlsp.Attribute) error {
	*b = both("saml:" + strings.Join(attr.Values, "+"))
	return nil
}

func (b *both) UnmarshalText(text []byte) error {
	*b = both("text:" + string(text))
	return nil
}

// set collects every value of an attribute, with its declared type.
type set map[string]string

func (s *set) UnmarshalSAMLAttribute(attr samlsp.Attribute) error {
	*s = set{}
	for i, v := range attr.Values {
		(*s)[v] = attr.Types[i]
	}
	return nil
}

// groups is a slice type that unmarshals the whole attribute itself.
type groups []string

func (g *groups) UnmarshalSAMLAttribute(attr samlsp.Attribute) error {
	*g = append(groups{"from:" + attr.Name}, attr.Values...)
	return nil
}

// strictBool accepts only values declared as xs:boolean.
type strictBool bool

func (b *strictBool) UnmarshalSAMLAttribute(attr samlsp.Attribute) error {
	if attr.Types[0] != "xs:boolean" {
		return errors.New("not declared xs:boolean")
	}
	*b = attr.Values[0] == "true" || attr.Values[0] == "1"
	return nil
}

func TestDecodeAttributesAttributeUnmarshaler(t *testing.T) {
	a := &samlsp.Assertion{Attributes: samlsp.Attributes{
		{Name: "x", NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", Values: []string{"a", "b"}, Types: []string{"xs:string", ""}},
		{Name: "y", Values: []string{"1"}},
		// A second element with the same Name adds to the values; its
		// missing Types count as undeclared.
		{Name: "x", Values: []string{"c"}},
		{Name: "flag", Values: []string{"true"}, Types: []string{"xs:boolean"}},
	}}

	var got struct {
		Both      both              `saml:"x"`
		BothSlice []both            `saml:"x"`
		Set       set               `saml:"x"`
		PSet      *set              `saml:"x"`
		Groups    groups            `saml:"x"`
		Raw       samlsp.Attribute  `saml:"x"`
		PRaw      *samlsp.Attribute `saml:"y"`
		Flag      strictBool        `saml:"flag"`
		Absent    *set              `saml:"absent"`
	}
	if err := a.DecodeAttributes(&got); err != nil {
		t.Fatal(err)
	}

	if got.Both != "saml:a+b+c" {
		t.Errorf("Both = %q: AttributeUnmarshaler not preferred, or not given every value", got.Both)
	}
	if len(got.BothSlice) != 3 || got.BothSlice[2] != "saml:c" {
		t.Errorf("BothSlice = %q: elements should each get one value", got.BothSlice)
	}
	if len(got.Set) != 3 || got.Set["a"] != "xs:string" || got.Set["c"] != "" {
		t.Errorf("Set = %v", got.Set)
	}
	if got.PSet == nil || len(*got.PSet) != 3 {
		t.Errorf("PSet = %v", got.PSet)
	}
	if strings.Join(got.Groups, ",") != "from:x,a,b,c" {
		t.Errorf("Groups = %q", got.Groups)
	}
	if got.Raw.Name != "x" || got.Raw.NameFormat == "" || len(got.Raw.Values) != 3 || len(got.Raw.Types) != 3 {
		t.Errorf("Raw = %+v", got.Raw)
	}
	if got.PRaw == nil || got.PRaw.Values[0] != "1" || got.PRaw.Types[0] != "" {
		t.Errorf("PRaw = %+v", got.PRaw)
	}
	if !got.Flag {
		t.Error("Flag not set")
	}
	if got.Absent != nil {
		t.Error("an absent attribute was unmarshaled")
	}

	// Errors are wrapped with the attribute and field.
	var strict struct {
		Y strictBool `saml:"y"`
	}
	err := a.DecodeAttributes(&strict)
	if err == nil || !strings.Contains(err.Error(), `attribute "y" into field Y`) || !strings.Contains(err.Error(), "not declared xs:boolean") {
		t.Errorf("err = %v", err)
	}
}

type Contact struct {
	Email string `saml:"mail"`
}

type Extra struct {
	Phone string `saml:"phone"`
}

func TestDecodeAttributesStructure(t *testing.T) {
	a := &samlsp.Assertion{Attributes: samlsp.Attributes{
		{Name: "mail", Values: []string{"alice@example.com"}},
		{Name: "groups", Values: []string{"a", "b"}},
		{Name: "one", Values: []string{"x"}},
		{Name: "role", NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic", Values: []string{"basic-role"}},
		{Name: "role", NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", Values: []string{"uri-role"}},
		{Name: "plain", Values: []string{"no format"}},
	}}

	var got struct {
		Contact            // embedded: flattened
		*Extra             // embedded pointer: allocated only if set
		Groups   [3]string `saml:"groups"`
		AnyMany  any       `saml:"groups"`
		AnyOne   any       `saml:"one"`
		Basic    string    `saml:"role,format=basic"`
		URI      string    `saml:"role,format=uri"`
		Full     string    `saml:"role,format=urn:oasis:names:tc:SAML:2.0:attrname-format:uri"`
		Plain    string    `saml:"plain,format=unspecified"`
		AnyRole  []string  `saml:"role"`
		WrongFmt string    `saml:"plain,format=uri"`
	}
	if err := a.DecodeAttributes(&got); err != nil {
		t.Fatal(err)
	}
	if got.Email != "alice@example.com" {
		t.Errorf("embedded Email = %q", got.Email)
	}
	if got.Extra != nil {
		t.Errorf("embedded pointer allocated without any field: %+v", got.Extra)
	}
	if got.Groups != [3]string{"a", "b", ""} {
		t.Errorf("Groups = %q", got.Groups)
	}
	if many, ok := got.AnyMany.([]string); !ok || len(many) != 2 {
		t.Errorf("AnyMany = %#v", got.AnyMany)
	}
	if got.AnyOne != "x" {
		t.Errorf("AnyOne = %#v", got.AnyOne)
	}
	if got.Basic != "basic-role" || got.URI != "uri-role" || got.Full != "uri-role" {
		t.Errorf("by format: %q %q %q", got.Basic, got.URI, got.Full)
	}
	if got.Plain != "no format" || got.WrongFmt != "" {
		t.Errorf("unspecified format: %q, %q", got.Plain, got.WrongFmt)
	}
	if len(got.AnyRole) != 2 {
		t.Errorf("without a format, any NameFormat: %q", got.AnyRole)
	}

	// An embedded pointer whose field is present is allocated.
	var withExtra struct {
		*Extra
	}
	b := &samlsp.Assertion{Attributes: samlsp.Attributes{{Name: "phone", Values: []string{"555"}}}}
	if err := b.DecodeAttributes(&withExtra); err != nil {
		t.Fatal(err)
	}
	if withExtra.Extra == nil || withExtra.Phone != "555" {
		t.Errorf("embedded pointer = %+v", withExtra.Extra)
	}

	// Errors.
	var small struct {
		G [1]string `saml:"groups"`
	}
	if err := a.DecodeAttributes(&small); err == nil || !strings.Contains(err.Error(), "do not fit") {
		t.Errorf("array too small: %v", err)
	}
	var badTag struct {
		X string `saml:"mail,omitempty"`
	}
	if err := a.DecodeAttributes(&badTag); err == nil || !strings.Contains(err.Error(), "unknown tag option") {
		t.Errorf("bad tag: %v", err)
	}
}

// address decodes a value of a complex type.
type address struct {
	Street string `xml:"Street"`
	City   string `xml:"City"`
}

func (a *address) UnmarshalSAMLAttribute(attr samlsp.Attribute) error {
	if len(attr.XML) == 0 || attr.XML[0] == "" {
		return errors.New("not a complex value")
	}
	return xml.Unmarshal([]byte("<address>"+attr.XML[0]+"</address>"), a)
}

func TestDecodeAttributesComplexValues(t *testing.T) {
	a := &samlsp.Assertion{Attributes: samlsp.Attributes{
		{Name: "address", Values: []string{"", ""}, XML: []string{
			`<Street xmlns="urn:example:address">1 Main St</Street><City xmlns="urn:example:address">Springfield</City>`,
			`<Street xmlns="urn:example:address">2 Oak Ave</Street>`,
		}},
		{Name: "plain", Values: []string{"x"}},
	}}
	var got struct {
		Home      address   `saml:"address"`
		Addresses []address `saml:"address"`
		Plain     string    `saml:"plain"`
	}
	if err := a.DecodeAttributes(&got); err != nil {
		t.Fatal(err)
	}
	if got.Home.Street != "1 Main St" || got.Home.City != "Springfield" {
		t.Errorf("Home = %+v", got.Home)
	}
	if len(got.Addresses) != 2 || got.Addresses[1].Street != "2 Oak Ave" {
		t.Errorf("Addresses = %+v", got.Addresses)
	}
	if got.Plain != "x" {
		t.Errorf("Plain = %q", got.Plain)
	}
}
