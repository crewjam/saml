package samlidp_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"testing"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlidp"
	"github.com/crewjam/saml/x/samlsp"
)

const (
	uriFormat   = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
	basicFormat = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
	unspecified = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"
	mailOID     = "urn:oid:0.9.2342.19200300.100.1.3"
)

func requested(name, format string, required bool, values ...string) saml.RequestedAttribute {
	ra := saml.RequestedAttribute{Attribute: saml.Attribute{Name: name, NameFormat: format}}
	for _, v := range values {
		ra.Values = append(ra.Values, saml.AttributeValue{Type: "xs:string", Value: v})
	}
	if required {
		ra.IsRequired = &required
	}
	return ra
}

// withAttributeServices returns a metadata edit that gives the SP services.
func withAttributeServices(services ...saml.AttributeConsumingService) func(*saml.EntityDescriptor) {
	return func(md *saml.EntityDescriptor) {
		md.SPSSODescriptors[0].AttributeConsumingServices = services
	}
}

func attributeService(index int, isDefault *bool, attrs ...saml.RequestedAttribute) saml.AttributeConsumingService {
	return saml.AttributeConsumingService{
		Index:               index,
		IsDefault:           isDefault,
		ServiceNames:        []saml.LocalizedName{{Lang: "en", Value: fmt.Sprintf("service %d", index)}},
		RequestedAttributes: attrs,
	}
}

func names(attrs []saml.RequestedAttribute) []string {
	if len(attrs) == 0 {
		return nil
	}
	out := make([]string, 0, len(attrs))
	for _, a := range attrs {
		out = append(out, a.Name)
	}
	return out
}

func withACSIndex(index string) samlsp.AuthnOption {
	return samlsp.WithAuthnRequest(func(req *saml.AuthnRequest) error {
		req.AttributeConsumingServiceIndex = index
		return nil
	})
}

// TestRequestedAttributesSelection checks which AttributeConsumingService
// RequestedAttributes chooses (saml-core §3.4.1, saml-metadata §2.4.4.1).
func TestRequestedAttributesSelection(t *testing.T) {
	yes, no := true, false
	ctx := context.Background()
	for _, tc := range []struct {
		name     string
		services []saml.AttributeConsumingService
		index    string
		want     []string
	}{
		{"none", nil, "", nil},
		{"first is default", []saml.AttributeConsumingService{
			attributeService(1, nil, requested("a", "", false)),
			attributeService(2, nil, requested("b", "", false)),
		}, "", []string{"a"}},
		{"isDefault", []saml.AttributeConsumingService{
			attributeService(1, &no, requested("a", "", false)),
			attributeService(2, &yes, requested("b", "", false)),
		}, "", []string{"b"}},
		{"index", []saml.AttributeConsumingService{
			attributeService(1, nil, requested("a", "", false)),
			attributeService(2, &yes, requested("b", "", false)),
		}, "1", []string{"a"}},
		{"index zero", []saml.AttributeConsumingService{
			attributeService(0, nil, requested("a", "", false)),
			attributeService(5, &yes, requested("b", "", false)),
		}, "0", []string{"a"}},
		{"index with whitespace and sign", []saml.AttributeConsumingService{
			attributeService(1, nil, requested("a", "", false)),
			attributeService(2, nil, requested("b", "", false)),
		}, " +2 ", []string{"b"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newPairWithMetadata(t, nil, nil, withAttributeServices(tc.services...))
			_, req, err := p.parse(t, withACSIndex(tc.index))
			if err != nil {
				t.Fatal(err)
			}
			got, err := p.idp.RequestedAttributes(ctx, req)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(names(got), tc.want) {
				t.Fatalf("got %q, want %q", names(got), tc.want)
			}
		})
	}
}

// TestRequestedAttributesUnknownIndex checks that an index the SP's
// metadata does not list is refused, not replaced by the default service,
// and only when the attributes are asked for.
func TestRequestedAttributesUnknownIndex(t *testing.T) {
	ctx := context.Background()
	for _, index := range []string{"9", "x", "65536", "-1"} {
		t.Run(index, func(t *testing.T) {
			p := newPairWithMetadata(t, nil, nil, withAttributeServices(
				attributeService(1, nil, requested("groups", "", false))))
			// ParseAuthnRequest does not look at the index.
			_, req, err := p.parse(t, withACSIndex(index))
			if err != nil {
				t.Fatal(err)
			}
			_, err = p.idp.RequestedAttributes(ctx, req)
			if !errors.Is(err, samlidp.ErrUnknownAttributeConsumingService) {
				t.Fatalf("got %v", err)
			}
			_ = asStatus(t, err, saml.StatusRequester, saml.StatusRequestUnsupported)

			_, err = p.idp.Response(ctx, req, testSubject, samlidp.ReleaseRequestedAttributesOnly())
			if !errors.Is(err, samlidp.ErrUnknownAttributeConsumingService) {
				t.Fatalf("Response: got %v", err)
			}
			// Without the option, Response is as it was.
			if _, err := p.idp.Response(ctx, req, testSubject); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestRequestedAttributesCopy checks that changing the result does not
// change the SP's metadata.
func TestRequestedAttributesCopy(t *testing.T) {
	ctx := context.Background()
	p := newPairWithMetadata(t, nil, nil, withAttributeServices(
		attributeService(1, nil, requested("groups", "", true, "admins"))))
	_, req, err := p.parse(t)
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.idp.RequestedAttributes(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	got[0].Name = "changed"
	got[0].Values[0].Value = "changed"
	*got[0].IsRequired = false
	again, err := p.idp.RequestedAttributes(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(again, []saml.RequestedAttribute{requested("groups", "", true, "admins")}) {
		t.Fatalf("got %+v", again)
	}
}

// TestReleaseRequestedAttributesOnly checks that Response releases only the
// attributes that the chosen service asks for, and, without the option,
// all of them.
func TestReleaseRequestedAttributesOnly(t *testing.T) {
	ctx := context.Background()
	p := newPairWithMetadata(t, nil, nil, withAttributeServices(
		attributeService(1, nil, requested(mailOID, uriFormat, true)),
		attributeService(2, nil, requested("groups", "", false, "users", "auditors"))))
	subject := testSubject
	subject.Attributes = append(subject.Attributes, samlidp.Attribute{Name: "secret", Values: []string{"s"}})

	released := func(opts []samlsp.AuthnOption, ropts ...samlidp.ResponseOption) []saml.Attribute {
		t.Helper()
		_, req, err := p.parse(t, opts...)
		if err != nil {
			t.Fatal(err)
		}
		var got []saml.Attribute
		ropts = append(ropts, samlidp.WithAssertion(func(a *saml.Assertion) error {
			for _, s := range a.AttributeStatements {
				got = append(got, s.Attributes...)
			}
			return nil
		}))
		msg, err := p.idp.Response(ctx, req, subject, ropts...)
		if err != nil {
			t.Fatal(err)
		}
		// What WithAssertion sees is what is sent.
		var sent []saml.Attribute
		for _, s := range decodeResponse(t, msg).Assertion.AttributeStatements {
			sent = append(sent, s.Attributes...)
		}
		if len(sent) != len(got) {
			t.Fatalf("sent %+v, WithAssertion saw %+v", sent, got)
		}
		return got
	}

	if got := released(nil); len(got) != 3 {
		t.Fatalf("without the option: got %+v", got)
	}
	got := released(nil, samlidp.ReleaseRequestedAttributesOnly())
	if len(got) != 1 || got[0].Name != mailOID || got[0].NameFormat != uriFormat || got[0].FriendlyName != "mail" ||
		len(got[0].Values) != 1 || got[0].Values[0].Value != "alice@example.com" {
		t.Fatalf("default service: got %+v", got)
	}
	got = released([]samlsp.AuthnOption{withACSIndex("2")}, samlidp.ReleaseRequestedAttributesOnly())
	if len(got) != 1 || got[0].Name != "groups" || len(got[0].Values) != 1 || got[0].Values[0].Value != "users" {
		t.Fatalf("service 2: got %+v", got)
	}

	// An SP that asks for nothing gets nothing.
	p = newPair(t, nil, nil)
	if got := released(nil, samlidp.ReleaseRequestedAttributesOnly()); len(got) != 0 {
		t.Fatalf("no service: got %+v", got)
	}
}

// TestFilterAttributes checks the matching of attributes by Name,
// NameFormat and values.
func TestFilterAttributes(t *testing.T) {
	mail := samlidp.Attribute{Name: mailOID, NameFormat: uriFormat, FriendlyName: "mail", Values: []string{"a@example.com"}}
	groups := samlidp.Attribute{Name: "groups", Values: []string{"admins", "users", "staff"}}
	basicGroups := samlidp.Attribute{Name: "groups", NameFormat: basicFormat, Values: []string{"admins"}}
	attrs := []samlidp.Attribute{mail, groups, basicGroups}

	for _, tc := range []struct {
		name      string
		requested []saml.RequestedAttribute
		want      []samlidp.Attribute
	}{
		{"nothing requested", nil, nil},
		{"name and format", []saml.RequestedAttribute{requested(mailOID, uriFormat, false)}, []samlidp.Attribute{mail}},
		{"format differs", []saml.RequestedAttribute{requested(mailOID, basicFormat, false)}, nil},
		{"name is case-sensitive", []saml.RequestedAttribute{requested("Groups", "", false)}, nil},
		{"FriendlyName does not match", []saml.RequestedAttribute{requested("mail", "", false)}, nil},
		{"no format matches any", []saml.RequestedAttribute{requested("groups", "", false)}, []samlidp.Attribute{groups, basicGroups}},
		{"unspecified matches any", []saml.RequestedAttribute{requested(mailOID, unspecified, false)}, []samlidp.Attribute{mail}},
		{"basic matches only basic", []saml.RequestedAttribute{requested("groups", basicFormat, false)}, []samlidp.Attribute{basicGroups}},
		{"unspecified attribute", []saml.RequestedAttribute{requested("groups", unspecified, false)}, []samlidp.Attribute{groups, basicGroups}},
		{"values", []saml.RequestedAttribute{requested("groups", basicFormat, false, "users")}, nil},
		{"values kept in order", []saml.RequestedAttribute{requested("groups", "", false, "staff", "admins", "other")},
			[]samlidp.Attribute{{Name: "groups", Values: []string{"admins", "staff"}}, basicGroups}},
		{"values of several", []saml.RequestedAttribute{
			requested("groups", "", false, "users"),
			requested("groups", "", false, "staff"),
		}, []samlidp.Attribute{{Name: "groups", Values: []string{"users", "staff"}}}},
		{"any value wins", []saml.RequestedAttribute{
			requested("groups", "", false, "users"),
			requested("groups", "", false),
		}, []samlidp.Attribute{groups, basicGroups}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := samlidp.FilterAttributes(tc.requested, attrs)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
	// attrs are not changed.
	if !reflect.DeepEqual(attrs[1].Values, []string{"admins", "users", "staff"}) {
		t.Fatalf("attrs changed: %+v", attrs)
	}
}

// TestMissingRequiredAttributes checks that only isRequired attributes
// that would not be released are reported.
func TestMissingRequiredAttributes(t *testing.T) {
	attrs := []samlidp.Attribute{
		{Name: mailOID, NameFormat: uriFormat, Values: []string{"a@example.com"}},
		{Name: "groups", Values: []string{"users"}},
	}
	reqMail := requested(mailOID, uriFormat, true)
	optional := requested("displayName", "", false)
	reqName := requested("displayName", "", true)
	reqAdmins := requested("groups", "", true, "admins")
	reqUsers := requested("groups", "", true, "users")
	reqWrongFormat := requested(mailOID, basicFormat, true)

	got := samlidp.MissingRequiredAttributes(
		[]saml.RequestedAttribute{reqMail, optional, reqName, reqAdmins, reqUsers, reqWrongFormat}, attrs)
	if want := []saml.RequestedAttribute{reqName, reqAdmins, reqWrongFormat}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	if got := samlidp.MissingRequiredAttributes([]saml.RequestedAttribute{reqMail, optional, reqUsers}, attrs); got != nil {
		t.Fatalf("got %+v", got)
	}
}

// This example sends an SP only the attributes its metadata asks for, and
// refuses the login if the user lacks one it requires.
func ExampleReleaseRequestedAttributesOnly() {
	var (
		config  *samlidp.Config
		req     *samlidp.AuthnRequest
		subject samlidp.Subject
		w       http.ResponseWriter
		r       *http.Request
	)

	requested, err := config.RequestedAttributes(r.Context(), req)
	var status *saml.StatusError
	if errors.As(err, &status) {
		// The request names an AttributeConsumingServiceIndex that the
		// SP's metadata does not list.
		msg, err := config.ErrorResponse(r.Context(), req, status)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		msg.Write(w)
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if missing := samlidp.MissingRequiredAttributes(requested, subject.Attributes); len(missing) > 0 {
		msg, err := config.ErrorResponse(r.Context(), req, &saml.StatusError{
			TopLevel:    saml.StatusResponder,
			SecondLevel: saml.StatusRequestDenied,
		})
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		msg.Write(w)
		return
	}
	msg, err := config.Response(r.Context(), req, subject, samlidp.ReleaseRequestedAttributesOnly())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	msg.Write(w)
}

// FilterAttributes keeps the attributes, and values, that the SP asks for.
func ExampleFilterAttributes() {
	required := true
	requested := []saml.RequestedAttribute{
		{Attribute: saml.Attribute{Name: "urn:oid:0.9.2342.19200300.100.1.3", NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"}, IsRequired: &required},
		{Attribute: saml.Attribute{Name: "groups", Values: []saml.AttributeValue{{Value: "staff"}}}},
		{Attribute: saml.Attribute{Name: "displayName"}, IsRequired: &required},
	}
	attrs := []samlidp.Attribute{
		{Name: "urn:oid:0.9.2342.19200300.100.1.3", NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", Values: []string{"alice@example.com"}},
		{Name: "groups", Values: []string{"admins", "staff"}},
		{Name: "employeeNumber", Values: []string{"1234"}},
	}
	for _, a := range samlidp.FilterAttributes(requested, attrs) {
		fmt.Println(a.Name, a.Values)
	}
	for _, ra := range samlidp.MissingRequiredAttributes(requested, attrs) {
		fmt.Println("missing:", ra.Name)
	}
	// Output:
	// urn:oid:0.9.2342.19200300.100.1.3 [alice@example.com]
	// groups [staff]
	// missing: displayName
}
