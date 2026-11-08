package idpslo_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlidp"
	"github.com/crewjam/saml/x/samlidp/idpslo"
)

// refusingServiceProvider is a saml.ServiceProviderProvider that knows no
// SP, and records that it was asked.
type refusingServiceProvider struct{ asked *bool }

func (p refusingServiceProvider) GetServiceProvider(*http.Request, string) (*saml.EntityDescriptor, error) {
	*p.asked = true
	return nil, errors.New("not this one")
}

// A ServiceProviderProvider that an IdentityProviderOption passed to
// ParseRequest sets is not used: the request is verified with the
// metadata of the ServiceProviderFunc, with which Response looks the SP
// up again.
func TestParseRequestServiceProviderProviderOption(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t, worldOptions{})
	_, a1 := w.login(t, 0, "s1")
	out, err := w.sps[0].slo.Request(ctx, a1.NameID, "")
	if err != nil {
		t.Fatal(err)
	}
	asked := false
	override := samlidp.WithIdentityProvider(func(idp *saml.IdentityProvider) {
		idp.ServiceProviderProvider = refusingServiceProvider{&asked}
	})
	req, err := w.logout.ParseRequest(ctx, toIDP(t, out), override)
	if err != nil {
		t.Fatal(err)
	}
	if asked {
		t.Fatal("the ServiceProviderProvider of the option was used")
	}
	if _, err := w.logout.Response(ctx, req); err != nil {
		t.Fatal(err)
	}
}

// A negative clock skew or issue delay set by an IdentityProviderOption is
// refused.
func TestNegativeTimeLimitOption(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t, worldOptions{})
	p, a1 := w.login(t, 0, "s1")
	out, err := w.sps[0].slo.Request(ctx, a1.NameID, "")
	if err != nil {
		t.Fatal(err)
	}
	negative := samlidp.WithIdentityProvider(func(idp *saml.IdentityProvider) { idp.MaxIssueDelay = -time.Hour })
	if _, err := w.logout.ParseRequest(ctx, toIDP(t, out), negative); err == nil {
		t.Error("ParseRequest accepted a negative issue delay")
	}
	if _, err := w.logout.Request(ctx, p, "", idpslo.WithIdentityProviderOptions(negative)); err == nil {
		t.Error("Request accepted a negative issue delay")
	}
	if _, err := w.logout.Request(ctx, p, ""); err != nil {
		t.Fatal(err)
	}
}
