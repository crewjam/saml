package samlsp_test

import (
	"bytes"
	"compress/flate"
	"context"
	"encoding/base64"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlsp"
)

func inflateParam(t *testing.T, u *url.URL, param string) []byte {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(u.Query().Get(param))
	if err != nil {
		t.Fatal(err)
	}
	buf, err := io.ReadAll(flate.NewReader(bytes.NewReader(data)))
	if err != nil {
		t.Fatal(err)
	}
	return buf
}

// sendToIDP sends a LogoutRequest message to ti's SLO endpoint and returns
// the IdP's answer.
func sendToIDP(t *testing.T, ti *testIDP, msg *samlsp.Message) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	ti.idp.ServeSLO(w, httptest.NewRequest(http.MethodGet, msg.RedirectURL().String(), nil))
	return w
}

func TestLogoutRequestReasonAndNotOnOrAfter(t *testing.T) {
	ti := newTestIDP(t)
	cfg := newTestConfig(t, ti)
	deadline := time.Now().Add(2 * time.Minute).Truncate(time.Millisecond)
	msg, err := cfg.LogoutRequest(t.Context(), saml.NameID{Value: "alice@example.com"}, "s",
		samlsp.WithReason(saml.LogoutReasonAdmin), samlsp.WithNotOnOrAfter(deadline))
	if err != nil {
		t.Fatal(err)
	}
	var req saml.LogoutRequest
	if err := xml.Unmarshal(inflateParam(t, msg.RedirectURL(), "SAMLRequest"), &req); err != nil {
		t.Fatal(err)
	}
	if req.Reason != saml.LogoutReasonAdmin || req.NotOnOrAfter == nil || !req.NotOnOrAfter.Equal(deadline) {
		t.Errorf("Reason %q, NotOnOrAfter %v", req.Reason, req.NotOnOrAfter)
	}
	// The IdP accepts it, signature and all.
	if w := sendToIDP(t, ti, msg); !ti.loggedOut {
		t.Errorf("IdP refused: %d %s", w.Code, w.Body.String())
	}
}

func TestEncryptLogoutNameID(t *testing.T) {
	ti := newTestIDP(t)
	cfg := newTestConfig(t, ti, samlsp.EncryptLogoutNameID)
	msg, err := cfg.LogoutRequest(t.Context(), saml.NameID{Format: string(saml.EmailAddressNameIDFormat), Value: "alice@example.com"}, "s")
	if err != nil {
		t.Fatal(err)
	}
	sent := string(inflateParam(t, msg.RedirectURL(), "SAMLRequest"))
	if !strings.Contains(sent, "EncryptedID") || strings.Contains(sent, "alice@example.com") {
		t.Fatalf("the NameID is not encrypted: %s", sent)
	}
	// The IdP decrypts it.
	if w := sendToIDP(t, ti, msg); !ti.loggedOut {
		t.Errorf("IdP refused: %d %s", w.Code, w.Body.String())
	}

	// An IdP without an encryption certificate.
	noEnc := newTestConfigWithIDP(t, ti, func(context.Context) (*saml.EntityDescriptor, error) {
		md := ti.idp.Metadata()
		for i := range md.IDPSSODescriptors {
			var kds []saml.KeyDescriptor
			for _, kd := range md.IDPSSODescriptors[i].KeyDescriptors {
				if kd.Use != "encryption" && kd.Use != "" {
					kds = append(kds, kd)
				}
			}
			md.IDPSSODescriptors[i].KeyDescriptors = kds
		}
		return md, nil
	}, samlsp.EncryptLogoutNameID)
	if _, err := noEnc.LogoutRequest(t.Context(), saml.NameID{Value: "alice"}, "s"); err == nil {
		t.Error("an unencryptable LogoutRequest was made")
	}
}

func TestLogoutResponseID(t *testing.T) {
	ti := newTestIDP(t)
	cfg := newTestConfig(t, ti)
	req := &samlsp.LogoutRequest{ID: "id-req", RelayState: "r"}
	for _, binding := range []string{saml.HTTPRedirectBinding, saml.HTTPPostBinding, saml.HTTPPostSimpleSignBinding} {
		msg, err := cfg.LogoutResponse(t.Context(), req, samlsp.WithBinding(binding))
		if err != nil {
			t.Fatal(err)
		}
		if msg.ID == "" {
			t.Errorf("%s: no ID", binding)
			continue
		}
		var sentID string
		if u := msg.RedirectURL(); u != nil {
			var resp saml.LogoutResponse
			if err := xml.Unmarshal(inflateParam(t, u, "SAMLResponse"), &resp); err != nil {
				t.Fatal(err)
			}
			sentID = resp.ID
		} else {
			w := httptest.NewRecorder()
			msg.Write(w)
			buf, err := base64.StdEncoding.DecodeString(formValues(w.Body.String()).Get("SAMLResponse"))
			if err != nil {
				t.Fatal(err)
			}
			var resp saml.LogoutResponse
			if err := xml.Unmarshal(buf, &resp); err != nil {
				t.Fatal(err)
			}
			sentID = resp.ID
		}
		if sentID != msg.ID {
			t.Errorf("%s: Message.ID %q, sent %q", binding, msg.ID, sentID)
		}
	}
}
