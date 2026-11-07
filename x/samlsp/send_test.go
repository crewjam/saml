package samlsp_test

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/beevik/etree"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlsp"
)

// pingRequest builds a made-up protocol message, to show that Send is not
// tied to the messages this package knows.
func pingRequest(issuer string) samlsp.OutgoingMessage {
	return samlsp.OutgoingMessage{
		Service: samlsp.SingleLogoutService, Param: "SAMLRequest", RelayState: "r", Sign: true,
		Build: func(_ *saml.ServiceProvider, destination string, modify func(any) error) (*etree.Element, error) {
			el := etree.NewElement("ex:Ping")
			el.CreateAttr("xmlns:ex", "urn:example")
			el.CreateAttr("ID", "id-ping")
			el.CreateAttr("Destination", destination)
			el.CreateElement("Issuer").SetText(issuer)
			if err := modify(el); err != nil {
				return nil, err
			}
			return el, nil
		},
	}
}

func TestSendCustomMessage(t *testing.T) {
	ti := newTestIDP(t)
	cfg := newTestConfig(t, ti)

	// WithModify applies to messages of its type only.
	touched := false
	msg, err := cfg.Send(t.Context(), pingRequest(spEntityID),
		samlsp.WithModify(func(el *etree.Element) error { el.CreateAttr("Extra", "yes"); return nil }),
		samlsp.WithModify(func(*saml.AuthnRequest) error { touched = true; return nil }),
		samlsp.WithBinding(saml.HTTPPostBinding))
	if err != nil {
		t.Fatal(err)
	}
	if touched {
		t.Error("a WithModify for another type ran")
	}
	if msg.ID != "id-ping" || msg.Destination != "https://idp.example.com/slo" || msg.Binding != saml.HTTPPostBinding {
		t.Errorf("message %+v", msg)
	}
	w := httptest.NewRecorder()
	msg.Write(w)
	sent := decodeFormMessage(t, w.Body.String(), "SAMLRequest")
	if !strings.Contains(sent, `Extra="yes"`) || !strings.Contains(sent, "SignatureValue") {
		t.Errorf("sent %s", sent)
	}
	// The signature is right after the Issuer.
	doc := etree.NewDocument()
	if err := doc.ReadFromString(sent); err != nil {
		t.Fatal(err)
	}
	if c := doc.Root().ChildElements(); len(c) < 2 || c[1].Tag != "Signature" {
		t.Error("the Signature is not after the Issuer")
	}

	// Redirect, with the query string signature.
	msg, err = cfg.Send(t.Context(), pingRequest(spEntityID))
	if err != nil {
		t.Fatal(err)
	}
	if q := msg.RedirectURL().Query(); q.Get("Signature") == "" || q.Get("RelayState") != "r" {
		t.Errorf("redirect %v", msg.RedirectURL())
	}

	// An error from WithModify, and invalid messages.
	boom := errors.New("boom")
	if _, err := cfg.Send(t.Context(), pingRequest(spEntityID), samlsp.WithModify(func(*etree.Element) error { return boom })); !errors.Is(err, boom) {
		t.Errorf("err = %v", err)
	}
	bad := pingRequest(spEntityID)
	bad.Param = "Other"
	if _, err := cfg.Send(t.Context(), bad); err == nil {
		t.Error("an invalid Param was accepted")
	}
	long := pingRequest(spEntityID)
	long.RelayState = strings.Repeat("x", 81)
	if _, err := cfg.Send(t.Context(), long); err == nil {
		t.Error("a long RelayState was accepted for a request")
	}
}

func decodeFormMessage(t *testing.T, body, param string) string {
	t.Helper()
	v := formValues(body).Get(param)
	buf, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(buf)
}

func TestWithCheckAndOptions(t *testing.T) {
	ti := newTestIDP(t)
	refuse := errors.New("refused")
	var seen *saml.ServiceProvider
	_, err := samlsp.New(staticIDP(ti), spEntityID,
		samlsp.Options(
			samlsp.WithServiceProvider(func(sp *saml.ServiceProvider) { sp.SignMetadata = true }),
			samlsp.WithCheck(func(sp *saml.ServiceProvider) error { seen = sp; return nil }),
		))
	if err != nil {
		t.Fatal(err)
	}
	if seen == nil || !seen.SignMetadata {
		t.Error("the check did not see the ServiceProviderOptions")
	}
	if _, err := samlsp.New(staticIDP(ti), spEntityID, samlsp.WithCheck(func(*saml.ServiceProvider) error { return refuse })); !errors.Is(err, refuse) {
		t.Errorf("err = %v", err)
	}
}

func TestNewMessage(t *testing.T) {
	msg := samlsp.NewMessage("id-1", saml.SOAPBinding, func(w http.ResponseWriter) { w.WriteHeader(http.StatusAccepted) })
	w := httptest.NewRecorder()
	msg.Write(w)
	if w.Code != http.StatusAccepted || msg.ID != "id-1" || msg.RedirectURL() != nil {
		t.Errorf("%d %+v", w.Code, msg)
	}
}
