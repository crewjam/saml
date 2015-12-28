package saml

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"text/template"
	"time"

	"github.com/crewjam/go-xmlsec"
	"github.com/crewjam/saml/metadata"
)

type IdentityProvider struct {
	Key              string
	Certificate      string
	MetadataURL      string
	SSOURL           string
	ServiceProviders map[string]*metadata.Metadata
	Users            []User

	sessions map[string]*Session
}

type User struct {
	Name     string
	Password string // XXX !!!
	Groups   []string
	Email    string

	CommonName string
	Surname    string
	GivenName  string
}

type Session struct {
	CreateTime time.Time
	Index      string
	User       *User
}

func randomBytes(n int) []byte {
	rv := make([]byte, n)
	if _, err := randReader.Read(rv); err != nil {
		panic(err)
	}
	return rv
}

func (idp *IdentityProvider) Metadata() *metadata.Metadata {
	cert, _ := pem.Decode([]byte(idp.Certificate))
	if cert == nil {
		panic("invalid IDP certificate")
	}
	certStr := base64.StdEncoding.EncodeToString(cert.Bytes)

	return &metadata.Metadata{
		EntityID:   idp.MetadataURL,
		ValidUntil: timeNow().Add(DefaultValidDuration),
		IDPSSODescriptor: &metadata.IDPSSODescriptor{
			ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
			KeyDescriptor: []metadata.KeyDescriptor{
				metadata.KeyDescriptor{
					Use: "signing",
					KeyInfo: metadata.KeyInfo{
						Certificate: certStr,
					},
				},
				metadata.KeyDescriptor{
					Use: "encryption",
					KeyInfo: metadata.KeyInfo{
						Certificate: certStr,
					},
					EncryptionMethods: []metadata.EncryptionMethod{
						metadata.EncryptionMethod{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes128-cbc"},
						metadata.EncryptionMethod{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes192-cbc"},
						metadata.EncryptionMethod{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes256-cbc"},
						metadata.EncryptionMethod{Algorithm: "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"},
					},
				},
			},
			NameIDFormat: []string{
				"urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
			},
			SingleSignOnService: []metadata.Endpoint{
				{
					Binding:  metadata.HTTPRedirectBinding,
					Location: idp.SSOURL,
				},
				{
					Binding:  metadata.HTTPPostBinding,
					Location: idp.SSOURL,
				},
			},
		},
	}
}

// ServeMetadata returns the IDP metadata
func (idp *IdentityProvider) ServeMetadata(w http.ResponseWriter, r *http.Request) {
	buf, _ := xml.MarshalIndent(metadata.EntitiesDescriptor{
		EntityDescriptor: []*metadata.Metadata{idp.Metadata()},
	}, "", "  ")
	w.Write(buf)
}

// ServeRedirectAuthnRequest handles SAML auth requests. When we get a request for a user that
// does not have a valid session with us, we invoke CreateSession(). The user's request flow may
// end up replaying the request once a valid session is established.
func (idp *IdentityProvider) ServeRedirectAuthnRequest(w http.ResponseWriter, r *http.Request) {
	var relayState string
	var reqBuf []byte
	switch r.Method {
	case "GET":
		compressedRequest, err := base64.StdEncoding.DecodeString(r.URL.Query().Get("SAMLRequest"))
		if err != nil {
			log.Printf("cannot decode request: %s", err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		reqBuf, err = ioutil.ReadAll(flate.NewReader(bytes.NewReader(compressedRequest)))
		if err != nil {
			log.Printf("cannot decompress request: %s", err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		relayState = r.URL.Query().Get("RelayState")
	case "POST":
		if err := r.ParseForm(); err != nil {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		var err error
		reqBuf, err = base64.StdEncoding.DecodeString(r.PostForm.Get("SAMLRequest"))
		if err != nil {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		relayState = r.PostForm.Get("RelayState")
	default:
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	authnRequest, serviceProviderMetadata, err := idp.validateAuthnRequest(reqBuf)
	if err != nil {
		log.Printf("failed to validate request: %s", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	session, sessionErr := idp.getOrCreateSession(w, r)

	// if we don't have a session, either from a cookie or from receiving
	// credentials, then prompt for one
	if session == nil {
		toast := ""
		if sessionErr == errInvalidUsernameOrPassword {
			toast = "Invalid username or password"
		}
		idp.sendLoginForm(w, r, reqBuf, relayState, toast)
		return
	}

	// the only response binding we support right now is the HTTP-POST binding. I'm not sure if other bindings are specified and/or
	// are in use or not.
	var binding = metadata.HTTPPostBinding
	var acsEndpoint = idp.getAssertionConsumerServiceEndpoint(serviceProviderMetadata, binding)
	if acsEndpoint == nil {
		log.Panicf("ServiceProvider %s: cannot find appropriate ACS endpoint for binding %s", serviceProviderMetadata.EntityID, binding)
	}

	// we have a valid session and must make a SAML assertion
	assertion := idp.makeAssertion(r, authnRequest, session, serviceProviderMetadata, acsEndpoint)
	signedAssertionBuf, err := idp.signAssertion(assertion)
	if err != nil {
		panic(err)
	}

	// encrypt the assertion
	encryptedAssertion, err := xmlsec.Encrypt(getSPEncryptionCert(serviceProviderMetadata),
		signedAssertionBuf, xmlsec.EncryptOptions{})
	if err != nil {
		panic(err)
	}

	response := &spResponse{
		Destination:  authnRequest.AssertionConsumerServiceURL,
		ID:           fmt.Sprintf("id-%x", randomBytes(16)),
		InResponseTo: authnRequest.ID,
		IssueInstant: timeNow(),
		Version:      "2.0",
		Issuer: &spIssuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  idp.MetadataURL,
		},
		Status: &spStatus{
			StatusCode: spStatusCode{
				Value: spStatusSuccess,
			},
		},
		EncryptedAssertion: &spEncryptedAssertion{
			EncryptedData: encryptedAssertion,
		},
	}

	responseBuf, _ := xml.Marshal(response)
	log.Printf("SAML RESPONSE: XXX %s XXX", responseBuf)

	idp.sendResponse(w, r, serviceProviderMetadata, relayState, response, acsEndpoint)
}

// getIDPSigningCert returns the certificate which we can use to verify things
// signed by the IDP in PEM format, or nil if no such certificate is found.
func getSPEncryptionCert(sp *metadata.Metadata) []byte {
	cert := ""
	for _, keyDescriptor := range sp.SPSSODescriptor.KeyDescriptor {
		if keyDescriptor.Use == "encryption" {
			cert = keyDescriptor.KeyInfo.Certificate
			break
		}
	}

	// If there are no explicitly signing certs, just return the first
	// non-empty cert we find.
	if cert == "" {
		for _, keyDescriptor := range sp.SPSSODescriptor.KeyDescriptor {
			if keyDescriptor.Use == "" && keyDescriptor.KeyInfo.Certificate != "" {
				cert = keyDescriptor.KeyInfo.Certificate
				break
			}
		}
	}

	if cert == "" {
		return nil
	}

	// cleanup whitespace and re-encode a PEM
	cert = regexp.MustCompile("\\s+").ReplaceAllString(cert, "")
	certBytes, _ := base64.StdEncoding.DecodeString(cert)
	certBytes = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes})
	return certBytes
}

func (idp *IdentityProvider) validateAuthnRequest(reqBuf []byte) (*spAuthRequest, *metadata.Metadata, error) {
	req := spAuthRequest{}
	if err := xml.Unmarshal(reqBuf, &req); err != nil {
		return nil, nil, err
	}

	// TODO(ross): is this supposed to be the metdata URL? or the target URL?
	//   i.e. should idp.SSOURL actually be idp.Metadata().EntityID?
	if req.Destination != idp.SSOURL {
		return nil, nil, fmt.Errorf("expected destination to be %q, not %q",
			idp.SSOURL, req.Destination)
	}
	if req.IssueInstant.Add(MaxIssueDelay).Before(timeNow()) {
		return nil, nil, fmt.Errorf("request expired at %s",
			req.IssueInstant.Add(MaxIssueDelay))
	}
	if req.Version != "2.0" {
		return nil, nil, fmt.Errorf("expected SAML request version 2, got %q", req.Version)
	}

	serviceProvider, serviceProviderFound := idp.ServiceProviders[req.Issuer.Text]
	if !serviceProviderFound {
		return nil, nil, fmt.Errorf("cannot handle request from unknown service provider %s",
			req.Issuer.Text)
	}

	acsValid := false
	for _, acsEndpoint := range serviceProvider.SPSSODescriptor.AssertionConsumerService {
		if req.AssertionConsumerServiceURL == acsEndpoint.Location {
			acsValid = true
			break
		}
	}
	if !acsValid {
		return nil, nil, fmt.Errorf("invalid ACS url specified in request: %s", req.AssertionConsumerServiceURL)
	}

	return &req, serviceProvider, nil
}

var errInvalidUsernameOrPassword = errors.New("invalid username or password")

// getOrCreateSession returns the *Session for this request. If the remote user has specified a username
// and password it is validated against the user database, and if valid, returns a newly
// created session object.
//
// If the remote user ahs specified invalid credentials, then the error returned is errInvalidUsernameOrPassword
//
// If a session cookie already exists and represents a valid session, then it is returned.
//
// If neither credentials nor a valid session cookie exist, then nil is returned for both the *Session and error.
func (idp *IdentityProvider) getOrCreateSession(w http.ResponseWriter, r *http.Request) (*Session, error) {
	if idp.sessions == nil { // XXX race condition!
		idp.sessions = map[string]*Session{}
	}

	// if we received login credentials then maybe we can create a session
	if r.Method == "POST" && r.PostForm.Get("user") != "" {
		for _, user := range idp.Users {
			if user.Name == r.PostForm.Get("user") && user.Password == r.PostForm.Get("password") {
				session := &Session{
					User:       &user,
					CreateTime: timeNow(),
					Index:      hex.EncodeToString(randomBytes(32)),
				}
				sessionID := base64.StdEncoding.EncodeToString(randomBytes(32))
				idp.sessions[sessionID] = session
				http.SetCookie(w, &http.Cookie{
					Name:     "session",
					Value:    sessionID,
					MaxAge:   int(cookieMaxAge.Seconds()),
					HttpOnly: false,
					Path:     "/",
				})
				return session, nil
			}
		}
		return nil, errInvalidUsernameOrPassword
	}

	sessionCookie, err := r.Cookie("session")
	if err == nil {
		session, ok := idp.sessions[sessionCookie.Value]
		if ok {
			return session, nil
		}
	}
	return nil, nil
}

// sendLoginForm produces a form which requests a username and password and directs the user
// back to the IDP authorize URL to restart the SAML login flow, this time establishing a
// session based on the credentials that were provided.
func (idp *IdentityProvider) sendLoginForm(w http.ResponseWriter, r *http.Request, reqBuf []byte, relayState string, toast string) {
	postURL := r.URL
	postURL.RawQuery = ""

	tmpl := template.Must(template.New("saml-post-form").Parse(`` +
		`<p>{{.Toast}}</p>` +
		`<form method="post" action="{{.URL}}">` +
		`<input type="text" name="user" placeholder="user" value="" />` +
		`<input type="password" name="password" placeholder="password" value="" />` +
		`<input type="hidden" name="SAMLRequest" value="{{.SAMLRequest}}" />` +
		`<input type="hidden" name="RelayState" value="{{.RelayState}}" />` +
		`<input type="submit" value="Log In" />` +
		`</form>`))
	data := struct {
		Toast       string
		URL         string
		SAMLRequest string
		RelayState  string
	}{
		Toast:       toast,
		URL:         postURL.String(),
		SAMLRequest: base64.StdEncoding.EncodeToString(reqBuf),
		RelayState:  relayState,
	}

	if err := tmpl.Execute(w, data); err != nil {
		panic(err)
	}
}

// makeAssertion produces a SAML assertion object from the specified user
// session.
func (idp *IdentityProvider) makeAssertion(r *http.Request, authnRequest *spAuthRequest, session *Session, serviceProvider *metadata.Metadata, acsEndpoint *metadata.IndexedEndpoint) *spAssertion {
	signatureTemplate := xmlsec.DefaultSignature([]byte(idp.Certificate))
	groupMemberAttributeValues := []spAttributeValue{}
	for _, group := range session.User.Groups {
		groupMemberAttributeValues = append(groupMemberAttributeValues, spAttributeValue{
			Type:  "xs:string",
			Value: group,
		})
	}
	assertion := spAssertion{
		ID:           hex.EncodeToString(randomBytes(32)),
		IssueInstant: timeNow(),
		Version:      "2.0",
		Issuer: &spIssuer{
			Format: "XXX",
			Value:  idp.Metadata().EntityID,
		},
		Signature: &signatureTemplate,
		Subject: &spSubject{
			NameID: &spNameID{
				Format:          "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
				NameQualifier:   idp.Metadata().EntityID,
				SPNameQualifier: serviceProvider.EntityID,
				Value:           session.User.Name, // XXX should be a hash or something
			},
			SubjectConfirmation: &spSubjectConfirmation{
				Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
				SubjectConfirmationData: spSubjectConfirmationData{
					Address:      r.RemoteAddr,
					InResponseTo: authnRequest.ID,
					NotOnOrAfter: timeNow().Add(MaxIssueDelay),
					Recipient:    acsEndpoint.Location,
				},
			},
		},
		Conditions: &spConditions{
			NotBefore:    timeNow(),
			NotOnOrAfter: timeNow().Add(MaxIssueDelay),
			AudienceRestriction: &spAudienceRestriction{
				Audience: &spAudience{Value: serviceProvider.EntityID},
			},
		},
		AuthnStatement: &spAuthnStatement{
			AuthnInstant: session.CreateTime,
			SessionIndex: session.Index,
			SubjectLocality: spSubjectLocality{
				Address: r.RemoteAddr,
			},
			AuthnContext: spAuthnContext{
				AuthnContextClassRef: &spAuthnContextClassRef{
					Value: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
				},
			},
		},
		AttributeStatement: &spAttributeStatement{
			Attributes: []spAttribute{
				spAttribute{
					FriendlyName: "uid",
					Name:         "urn:oid:0.9.2342.19200300.100.1.1",
					NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
					Values: []spAttributeValue{spAttributeValue{
						Type:  "xs:string",
						Value: session.User.Name,
					}},
				},
				spAttribute{
					FriendlyName: "eduPersonPrincipalName",
					Name:         "urn:oid:1.3.6.1.4.1.5923.1.1.1.6",
					NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
					Values: []spAttributeValue{spAttributeValue{
						Type:  "xs:string",
						Value: session.User.Email,
					}},
				},
				spAttribute{
					FriendlyName: "sn",
					Name:         "urn:oid:2.5.4.4",
					NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
					Values: []spAttributeValue{spAttributeValue{
						Type:  "xs:string",
						Value: session.User.Surname,
					}},
				},
				spAttribute{
					FriendlyName: "givenName",
					Name:         "urn:oid:2.5.4.42",
					NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
					Values: []spAttributeValue{spAttributeValue{
						Type:  "xs:string",
						Value: session.User.GivenName,
					}},
				},
				spAttribute{
					FriendlyName: "cn",
					Name:         "urn:oid:2.5.4.3",
					NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
					Values: []spAttributeValue{spAttributeValue{
						Type:  "xs:string",
						Value: session.User.CommonName,
					}},
				},
				spAttribute{
					FriendlyName: "eduPersonAffiliation",
					Name:         "urn:oid:1.3.6.1.4.1.5923.1.1.1.1",
					NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
					Values:       groupMemberAttributeValues,
				},
			},
		},
	}
	return &assertion
}

func (idp *IdentityProvider) signAssertion(assertion *spAssertion) ([]byte, error) {
	assertionBuf, err := xml.Marshal(assertion)
	if err != nil {
		return nil, err
	}

	signedAssertionBuf, err := xmlsec.Sign([]byte(idp.Key), assertionBuf, xmlsec.SignatureOptions{})
	if err != nil {
		return nil, err
	}
	ioutil.WriteFile("idp-signed-assertion.xml", signedAssertionBuf, 0644)

	return signedAssertionBuf, nil
}

func (idp *IdentityProvider) getAssertionConsumerServiceEndpoint(serviceProviderMetadata *metadata.Metadata, binding string) *metadata.IndexedEndpoint {
	var rv *metadata.IndexedEndpoint
	for _, acsEndpointCandidate := range serviceProviderMetadata.SPSSODescriptor.AssertionConsumerService {
		if acsEndpointCandidate.Binding != binding {
			continue
		}
		if rv == nil || rv.Index < acsEndpointCandidate.Index {
			rv = &acsEndpointCandidate
		}
	}
	return rv
}

func (idp *IdentityProvider) sendResponse(w http.ResponseWriter, r *http.Request, serviceProviderMetadata *metadata.Metadata, relayState string, response *spResponse, acsEndpoint *metadata.IndexedEndpoint) {
	responseBuf, err := xml.Marshal(response)
	if err != nil {
		log.Panicf("marshal response: %s", err)
	}

	switch acsEndpoint.Binding {
	case metadata.HTTPPostBinding:
		tmpl := template.Must(template.New("saml-post-form").Parse(`<html>` +
			`<form method="post" action="{{.URL}}" id="SAMLResponseForm">` +
			`<input type="hidden" name="SAMLResponse" value="{{.SAMLResponse}}" />` +
			`<input type="hidden" name="RelayState" value="{{.RelayState}}" />` +
			`<input type="submit" value="Continue" />` +
			`</form>` +
			`<script>document.getElementById('SAMLResponseForm').submit();</script>` +
			`</html>`))
		data := struct {
			URL          string
			SAMLResponse string
			RelayState   string
		}{
			URL:          acsEndpoint.Location,
			SAMLResponse: base64.StdEncoding.EncodeToString(responseBuf),
			RelayState:   relayState,
		}
		tmpl.Execute(w, data)
		return

	default:
		log.Panicf("ServiceProvider %s: unsupported binding %s", serviceProviderMetadata.EntityID, acsEndpoint.Binding)
	}
}
