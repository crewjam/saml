package saml

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/beevik/etree"

	"github.com/crewjam/saml/internal/signerutil"
	"github.com/crewjam/saml/internal/xmlroundtrip"
)

// SessionParticipant is a service provider that an IdP session was used to
// log in to: a session participant in the sense of saml-profiles-2.0-os
// §4.4. The IdP records one each time it issues an assertion for the
// session, and sends it a LogoutRequest when the session is logged out.
type SessionParticipant struct {
	// ServiceProviderID is the entity ID of the service provider, as
	// passed to ServiceProviderProvider.GetServiceProvider.
	ServiceProviderID string

	// NameID is the NameID of the assertion issued to the service provider,
	// and SessionIndex the SessionIndex of its AuthnStatement (empty if it
	// had none). The LogoutRequest sent to the service provider carries
	// them.
	NameID       NameID
	SessionIndex string
}

// SessionParticipantTracker is an optional interface that a SessionProvider
// may implement to record the service providers each IdP session is used
// for, which single logout needs to propagate a logout to all of them
// (saml-profiles-2.0-os §4.4.3.3 and §4.4.4.2).
//
// If the SessionProvider implements it:
//
//   - ServeSSO and ServeIDPInitiated call AddSessionParticipant before
//     sending an assertion. If it fails, the assertion is not sent.
//   - StartLogout (IdP-initiated logout) sends a LogoutRequest to every
//     participant of the session.
//   - ServeSLO, for a LogoutRequest from a service provider, sends a
//     LogoutRequest to every other participant of the sessions it ends
//     before it answers the service provider.
//
// Without it, ServeSLO only ends the IdP session, and StartLogout contacts
// no service provider.
type SessionParticipantTracker interface {
	// AddSessionParticipant records that an assertion for session was
	// issued to participant. Recording the same participant twice should
	// not make it appear twice.
	AddSessionParticipant(r *http.Request, session *Session, participant SessionParticipant) error

	// SessionParticipants returns the participants recorded for every
	// session for which match returns true. ServeSLO calls it before it
	// ends the sessions (see SessionInvalidator), with
	// IdpLogoutRequest.MatchesSession; StartLogout calls it with a function
	// that matches its session by ID.
	SessionParticipants(r *http.Request, match func(*Session) bool) ([]SessionParticipant, error)
}

// recordSessionParticipant records the service provider of req as a
// participant of session, if the SessionProvider is a
// SessionParticipantTracker. It is called once req.Assertion is made.
func (idp *IdentityProvider) recordSessionParticipant(r *http.Request, req *IdpAuthnRequest, session *Session) error {
	tracker, ok := idp.SessionProvider.(SessionParticipantTracker)
	if !ok || req.Assertion == nil || req.Assertion.Subject == nil || req.Assertion.Subject.NameID == nil || req.ServiceProviderMetadata == nil {
		return nil
	}
	participant := SessionParticipant{
		ServiceProviderID: req.ServiceProviderMetadata.EntityID,
		NameID:            *req.Assertion.Subject.NameID,
	}
	for _, statement := range req.Assertion.AuthnStatements {
		if statement.SessionIndex != "" {
			participant.SessionIndex = statement.SessionIndex
			break
		}
	}
	if err := tracker.AddSessionParticipant(r, session, participant); err != nil {
		return fmt.Errorf("cannot record session participant %s: %w", participant.ServiceProviderID, err)
	}
	return nil
}

// sessionParticipants returns the distinct participants of the sessions
// match selects, leaving out those of the service provider exclude. tracked
// is false if the SessionProvider does not track participants.
func (idp *IdentityProvider) sessionParticipants(r *http.Request, match func(*Session) bool, exclude string) (participants []SessionParticipant, tracked bool, err error) {
	participants, _, tracked, err = idp.sessionParticipantsOf(r, match, exclude)
	return participants, tracked, err
}

// sessionParticipantsOf is sessionParticipants, and also reports whether
// exclude may be a participant of the sessions match selects: false only
// when the tracker lists participants for them and exclude is not one of
// them. With no tracker, a tracker error or no participants recorded,
// nothing is known, and isParticipant is true.
func (idp *IdentityProvider) sessionParticipantsOf(r *http.Request, match func(*Session) bool, exclude string) (participants []SessionParticipant, isParticipant bool, tracked bool, err error) {
	tracker, ok := idp.SessionProvider.(SessionParticipantTracker)
	if !ok {
		return nil, true, false, nil
	}
	all, err := tracker.SessionParticipants(r, match)
	if err != nil {
		return nil, true, true, err
	}
	isParticipant = len(all) == 0
	seen := map[string]bool{}
	for _, participant := range all {
		if participant.ServiceProviderID == exclude && exclude != "" {
			isParticipant = true
			continue
		}
		if participant.ServiceProviderID == "" {
			continue
		}
		key, err := json.Marshal(participant)
		if err != nil {
			return nil, true, true, err
		}
		if seen[string(key)] {
			continue
		}
		seen[string(key)] = true
		participants = append(participants, participant)
	}
	return participants, isParticipant, true, nil
}

// participantsUnknown reports whether a logout cannot reach every other
// session participant because they are not known, given what
// sessionParticipants returned: the tracker failed to list them, or there
// is no tracker and ReportPartialLogoutWithoutTracker is set. The logout is
// then answered with StatusPartialLogout (saml-core-2.0-os §3.7.3.2).
func (idp *IdentityProvider) participantsUnknown(tracked bool, err error) bool {
	if tracked {
		return err != nil
	}
	return idp.ReportPartialLogoutWithoutTracker
}

// StartLogout starts IdP-initiated single logout (saml-profiles-2.0-os
// §4.4.3.3) of session. Each service provider the session was used for
// (see SessionParticipantTracker) is sent a signed LogoutRequest, one at a
// time.
//
// A service provider whose metadata lists a SingleLogoutService with the
// SOAP binding is sent it server to server, over the SOAP binding, with
// HTTPClient; the browser does not leave the IdP. Its LogoutResponse must be
// signed by the service provider and is checked as one that comes back
// through the browser is, except that it may omit its Destination. If that
// fails (the service provider cannot be reached, its response is invalid or
// its status is not Success), the service provider is tried again through
// the browser, as below, if its metadata lists a front-channel endpoint: the
// browser may reach a service provider the IdP cannot, and logging the
// user's browser out there is better than not at all.
//
// Otherwise the browser is sent to the service provider with the
// LogoutRequest, using the HTTP-Redirect binding if the service provider's
// metadata lists a SingleLogoutService with it and HTTP-POST otherwise. It
// answers with a LogoutResponse to LogoutURL, which ServeSLO handles. The
// progress of the logout is kept in a cookie signed with the IdP's key and
// scoped to LogoutURL.
//
// Once every service provider has answered, or could not be contacted, the
// browser is redirected to returnURL, or, if returnURL is empty, shown a page
// that says the user is logged out, and which service providers could not
// log the user out. returnURL is only ever set by the caller, never taken
// from the request.
//
// StartLogout does not end the IdP session itself. As it writes the
// response, set any header that ends it (such as an expired session cookie)
// before calling it, and delete the session afterwards: the
// SessionParticipantTracker must still know the session when StartLogout
// asks it for the participants. session.ID identifies the session.
//
// If the SessionProvider does not implement SessionParticipantTracker, or
// the session has no participants, the logout finishes at once.
func (idp *IdentityProvider) StartLogout(w http.ResponseWriter, r *http.Request, session *Session, returnURL string) {
	var participants []SessionParticipant
	if session != nil && session.ID != "" {
		var err error
		participants, _, err = idp.sessionParticipants(r, func(s *Session) bool {
			return s != nil && s.ID == session.ID
		}, "")
		if err != nil {
			idp.Logger.Printf("failed to find the participants of the session to log out: %s", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}
	idp.continueLogout(w, r, &logoutState{
		Expires:   idp.now().Add(LogoutStateLifetime),
		Pending:   pendingParticipants(participants),
		ReturnURL: returnURL,
	})
}

// propagateLogout continues the handling of the valid LogoutRequest req, for
// which the IdP session has been ended, by sending a LogoutRequest to each
// of participants before answering req (saml-profiles-2.0-os §4.4.4.2).
func (idp *IdentityProvider) propagateLogout(w http.ResponseWriter, r *http.Request, req *IdpLogoutRequest, participants []SessionParticipant) {
	idp.continueLogout(w, r, &logoutState{
		Expires: idp.now().Add(LogoutStateLifetime),
		Pending: pendingParticipants(participants),
		Initiator: &logoutInitiator{
			ServiceProviderID: req.ServiceProviderMetadata.EntityID,
			RequestID:         req.Request.ID,
			RelayState:        req.RelayState,
			SLOEndpoint:       *req.SLOEndpoint,
		},
	})
}

// LogoutStateLifetime is how long a single logout that the IdP propagates to
// several service providers may take, from its start to the last
// LogoutResponse.
var LogoutStateLifetime = 15 * time.Minute

// logoutStateCookieName is the name of the cookie that holds the
// logoutState of a single logout the IdP is propagating.
const logoutStateCookieName = "saml_idp_logout"

// logoutState is the progress of a single logout that the IdP propagates to
// the participants of the session, one at a time.
type logoutState struct {
	// Expires is when the logout is abandoned.
	Expires time.Time `json:"exp"`

	// Pending are the participants still to be sent a LogoutRequest.
	Pending []pendingParticipant `json:"pending,omitempty"`

	// Current is the participant the outstanding LogoutRequest, whose ID
	// is RequestID, was sent to, or nil. Only its ServiceProviderID is
	// kept: nothing else is needed to check the LogoutResponse.
	Current   *SessionParticipant `json:"current,omitempty"`
	RequestID string              `json:"requestId,omitempty"`

	// Failed are the entity IDs of the participants that could not be
	// sent a LogoutRequest or did not answer it with success.
	Failed []string `json:"failed,omitempty"`

	// Dropped counts the participants that were given up on because the
	// state would not have fit in its cookie (see setLogoutStateCookie).
	// They are not named in Failed, which would not fit either.
	Dropped int `json:"dropped,omitempty"`

	// Initiator is the service provider whose LogoutRequest started the
	// logout, which is answered at the end, or nil for IdP-initiated logout,
	// which ends at ReturnURL.
	Initiator *logoutInitiator `json:"initiator,omitempty"`
	ReturnURL string           `json:"returnUrl,omitempty"`
}

// pendingParticipant is a participant of a logout in progress that has not
// yet been sent a LogoutRequest, as kept in the logout state cookie. The
// JSON names are those of SessionParticipant, which the state held before,
// so that a logout in progress during an upgrade carries on.
//
// Unless LogoutStateKey is set, the cookie is signed, not encrypted. So
// that it does not then hold in the clear the NameIDs that
// EncryptLogoutNameID keeps out of the LogoutRequests, sealLogoutNameIDs
// replaces NameID, before the state is
// written to the cookie, with EncryptedID: the saml:EncryptedID that the
// LogoutRequest to the participant then carries, encrypted to its service
// provider's encryption certificate. To save room in the cookie, that
// certificate, which the EncryptedKey names in its KeyInfo, is left out
// of it, and put back from the metadata when the LogoutRequest is made
// (see unsealLogoutNameID).
type pendingParticipant struct {
	ServiceProviderID string  `json:"ServiceProviderID"`
	NameID            *NameID `json:"NameID,omitempty"`
	SessionIndex      string  `json:"SessionIndex,omitempty"`

	// EncryptedID is the serialized saml:EncryptedID element that replaces
	// NameID, or empty.
	EncryptedID string `json:"EncryptedID,omitempty"`
}

// pendingParticipants returns participants as pending participants.
func pendingParticipants(participants []SessionParticipant) []pendingParticipant {
	pending := make([]pendingParticipant, 0, len(participants))
	for _, participant := range participants {
		nameID := participant.NameID
		pending = append(pending, pendingParticipant{
			ServiceProviderID: participant.ServiceProviderID,
			NameID:            &nameID,
			SessionIndex:      participant.SessionIndex,
		})
	}
	return pending
}

// participant returns p as a SessionParticipant, with an empty NameID if
// it has been replaced by an EncryptedID, and that EncryptedID, or nil.
func (p pendingParticipant) participant() (SessionParticipant, *etree.Element, error) {
	participant := SessionParticipant{
		ServiceProviderID: p.ServiceProviderID,
		SessionIndex:      p.SessionIndex,
	}
	if p.NameID != nil {
		participant.NameID = *p.NameID
	}
	if p.EncryptedID == "" {
		return participant, nil, nil
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromString(p.EncryptedID); err != nil {
		return participant, nil, fmt.Errorf("cannot read the encrypted NameID: %w", err)
	}
	if doc.Root() == nil {
		return participant, nil, errors.New("cannot read the encrypted NameID: no element")
	}
	return participant, doc.Root(), nil
}

// sealLogoutNameIDs replaces, if EncryptLogoutNameID is set and
// LogoutStateKey is not, the NameID of each pending participant of state
// with the EncryptedID that the LogoutRequest to it will carry (see
// pendingParticipant). With LogoutStateKey the whole state is encrypted
// instead, which takes far less room. A participant
// whose service provider publishes no encryption certificate keeps its
// NameID, which it is sent in the clear anyway. One whose metadata cannot
// be found, or whose NameID cannot be encrypted, is given up on and added
// to state.Failed, as it would be when its turn came.
func (idp *IdentityProvider) sealLogoutNameIDs(r *http.Request, state *logoutState) {
	if !idp.EncryptLogoutNameID || idp.LogoutStateKey != nil {
		return
	}
	pending := state.Pending[:0]
	for _, p := range state.Pending {
		if p.NameID == nil || p.EncryptedID != "" {
			pending = append(pending, p)
			continue
		}
		encryptedID, err := idp.sealLogoutNameID(r, p)
		if err != nil {
			idp.Logger.Printf("cannot send logout request to %s: %s", p.ServiceProviderID, err)
			state.Failed = append(state.Failed, p.ServiceProviderID)
			continue
		}
		if encryptedID != "" {
			p.NameID, p.EncryptedID = nil, encryptedID
		}
		pending = append(pending, p)
	}
	state.Pending = pending
}

// sealLogoutNameID returns the serialized saml:EncryptedID of the NameID of
// p, encrypted as for the LogoutRequest to it (see encryptLogoutNameID)
// but without the certificate it is encrypted to, or "" if its service
// provider publishes no encryption certificate.
func (idp *IdentityProvider) sealLogoutNameID(r *http.Request, p pendingParticipant) (string, error) {
	metadata, err := idp.participantMetadata(r, SessionParticipant{ServiceProviderID: p.ServiceProviderID})
	if err != nil {
		return "", err
	}
	encryptedID, cert, err := idp.encryptLogoutIdentifier(p.NameID, metadata)
	if err != nil || encryptedID == nil {
		return "", err
	}
	setX509Certificates(encryptedID, base64.StdEncoding.EncodeToString(cert.Raw), "")
	doc := etree.NewDocument()
	doc.SetRoot(encryptedID)
	return doc.WriteToString()
}

// unsealLogoutNameID puts back in encryptedID, made by sealLogoutNameID,
// the certificate it is encrypted to, from metadata, the metadata of the
// participant's service provider.
func unsealLogoutNameID(encryptedID *etree.Element, metadata *EntityDescriptor) error {
	cert, _, err := spEncryptionKey(metadata)
	if err != nil {
		return fmt.Errorf("service provider encryption certificate: %w", err)
	}
	setX509Certificates(encryptedID, "", base64.StdEncoding.EncodeToString(cert.Raw))
	return nil
}

// setX509Certificates sets to value the text of every ds:X509Certificate
// element in el whose text is old.
func setX509Certificates(el *etree.Element, old, value string) {
	for _, child := range el.ChildElements() {
		if child.Tag == "X509Certificate" && child.NamespaceURI() == "http://www.w3.org/2000/09/xmldsig#" && strings.TrimSpace(child.Text()) == old {
			child.SetText(value)
			continue
		}
		setX509Certificates(child, old, value)
	}
}

// logoutInitiator is the LogoutRequest that started an SP-initiated logout.
type logoutInitiator struct {
	ServiceProviderID string   `json:"sp"`
	RequestID         string   `json:"id"`
	RelayState        string   `json:"relayState,omitempty"`
	SLOEndpoint       Endpoint `json:"endpoint"`
}

// partial reports whether some participant of the logout was not logged
// out.
func (state *logoutState) partial() bool {
	return len(state.Failed) > 0 || state.Dropped > 0
}

// continueLogout sends a LogoutRequest to the next participant of state that
// can be sent one, and finishes the logout when there is none left.
func (idp *IdentityProvider) continueLogout(w http.ResponseWriter, r *http.Request, state *logoutState) {
	state.Current = nil
	state.RequestID = ""
	// The SOAP requests made before the browser is answered share one
	// deadline (see BackChannelLogoutTimeout).
	soapCtx, cancel := context.WithTimeout(r.Context(), BackChannelLogoutTimeout)
	defer cancel()
	for len(state.Pending) > 0 {
		pending := state.Pending[0]
		state.Pending = state.Pending[1:]
		if idp.logoutParticipant(soapCtx, w, r, state, pending) {
			return
		}
	}
	idp.finishLogout(w, r, state)
}

// logoutParticipant logs participant out. If its metadata lists a SOAP
// SingleLogoutService, it is sent a LogoutRequest over the SOAP binding
// first (see logoutParticipantSOAP). If it has none, or that fails, the
// browser is sent to its HTTP-Redirect or HTTP-POST SingleLogoutService
// with a LogoutRequest, and logoutParticipant returns true: the response
// has been written, and the logout continues when the participant's
// LogoutResponse arrives. A participant that cannot be logged out either
// way is added to state.Failed. The SOAP request is bounded by soapCtx; once
// it is done, the SOAP binding is not tried.
func (idp *IdentityProvider) logoutParticipant(soapCtx context.Context, w http.ResponseWriter, r *http.Request, state *logoutState, pending pendingParticipant) bool {
	participant, encryptedID, err := pending.participant()
	if err != nil {
		idp.Logger.Printf("cannot send logout request to %s: %s", participant.ServiceProviderID, err)
		state.Failed = append(state.Failed, participant.ServiceProviderID)
		return false
	}
	metadata, err := idp.participantMetadata(r, participant)
	if err == nil && encryptedID != nil {
		err = unsealLogoutNameID(encryptedID, metadata)
	}
	if err != nil {
		idp.Logger.Printf("cannot send logout request to %s: %s", participant.ServiceProviderID, err)
		state.Failed = append(state.Failed, participant.ServiceProviderID)
		return false
	}

	if soapCtx.Err() != nil {
		err = fmt.Errorf("no time left for the SOAP binding (BackChannelLogoutTimeout): %w", soapCtx.Err())
	} else {
		err = idp.logoutParticipantSOAP(soapCtx, metadata, participant, encryptedID)
	}
	switch {
	case err == nil:
		return false
	case errors.Is(err, ErrNoSOAPLogoutEndpoint):
	default:
		idp.Logger.Printf("back-channel logout of %s failed: %s", participant.ServiceProviderID, err)
	}

	if err := idp.sendLogoutRequest(w, r, state, participant, encryptedID, metadata); err != nil {
		idp.Logger.Printf("cannot send logout request to %s: %s", participant.ServiceProviderID, err)
		state.Failed = append(state.Failed, participant.ServiceProviderID)
		return false
	}
	return true
}

// participantMetadata returns the metadata of the service provider of
// participant.
func (idp *IdentityProvider) participantMetadata(r *http.Request, participant SessionParticipant) (*EntityDescriptor, error) {
	if idp.ServiceProviderProvider == nil {
		return nil, errors.New("IdentityProvider.ServiceProviderProvider is not set")
	}
	metadata, err := idp.ServiceProviderProvider.GetServiceProvider(r, participant.ServiceProviderID)
	if err != nil {
		return nil, err
	}
	if metadata == nil {
		return nil, errors.New("no metadata")
	}
	return metadata, nil
}

// MakeLogoutRequest returns an unsigned LogoutRequest that asks the
// service provider of participant, whose metadata is metadata, to end the
// session participant describes: it carries participant's NameID and
// SessionIndex, and is addressed to destination, a SingleLogoutService of
// metadata. If EncryptLogoutNameID is set, the NameID is encrypted to the
// encryption certificate of metadata, if it has one. Sign it, and send it
// with the binding of destination; check the answer with
// ValidateLogoutResponse. It is what StartLogout and ServeSLO send to
// session participants, for an application that sends LogoutRequests
// itself.
func (idp *IdentityProvider) MakeLogoutRequest(metadata *EntityDescriptor, participant SessionParticipant, destination string) (*LogoutRequest, error) {
	if metadata == nil {
		return nil, errors.New("no service provider metadata")
	}
	return idp.participantLogoutRequest(participant, nil, destination, metadata)
}

// participantLogoutRequest returns an unsigned LogoutRequest for the
// session of participant, addressed to destination. If encryptedID is not
// nil, it identifies the principal: it is the NameID of participant,
// already encrypted (see sealLogoutNameIDs). Otherwise, if
// EncryptLogoutNameID is set, its NameID is encrypted to the encryption
// certificate in metadata, the metadata of the participant's service
// provider (see encryptLogoutNameID).
func (idp *IdentityProvider) participantLogoutRequest(participant SessionParticipant, encryptedID *etree.Element, destination string, metadata *EntityDescriptor) (*LogoutRequest, error) {
	nameID := participant.NameID
	logoutRequest := &LogoutRequest{
		ID:           fmt.Sprintf("id-%x", randomBytes(idp.randReader(), 20)),
		Version:      "2.0",
		IssueInstant: idp.now(),
		Destination:  destination,
		Issuer: &Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  idp.MetadataURL.String(),
		},
		NameID: &nameID,
	}
	if participant.SessionIndex != "" {
		logoutRequest.SessionIndex = &SessionIndex{Value: participant.SessionIndex}
	}
	if encryptedID != nil {
		logoutRequest.NameID = nil
		logoutRequest.EncryptedID = encryptedID.Copy()
		return logoutRequest, nil
	}
	if idp.EncryptLogoutNameID {
		if err := idp.encryptLogoutNameID(logoutRequest, metadata); err != nil {
			return nil, err
		}
	}
	return logoutRequest, nil
}

// sendLogoutRequest sends the browser with a signed LogoutRequest for
// participant (identified by encryptedID if it is not nil; see
// participantLogoutRequest) to its HTTP-Redirect or HTTP-POST
// SingleLogoutService, as listed in metadata, and records it in state. It
// returns errors before it starts writing to w.
func (idp *IdentityProvider) sendLogoutRequest(w http.ResponseWriter, r *http.Request, state *logoutState, participant SessionParticipant, encryptedID *etree.Element, metadata *EntityDescriptor) error {
	endpoint, err := logoutRequestEndpoint(metadata)
	if err != nil {
		return err
	}
	logoutRequest, err := idp.participantLogoutRequest(participant, encryptedID, endpoint.Location, metadata)
	if err != nil {
		return err
	}

	write, err := idp.logoutRequestWriter(logoutRequest, endpoint.Binding)
	if err != nil {
		return err
	}
	state.Current = &SessionParticipant{ServiceProviderID: participant.ServiceProviderID}
	state.RequestID = logoutRequest.ID
	if err := idp.setLogoutStateCookie(w, r, state); err != nil {
		state.Current, state.RequestID = nil, ""
		return err
	}
	write(w, r)
	return nil
}

// encryptLogoutNameID replaces the NameID of logoutRequest with a
// saml:EncryptedID holding it, encrypted to the encryption certificate in
// metadata, the service provider's metadata. If metadata has no encryption
// certificate, logoutRequest is left as it is.
func (idp *IdentityProvider) encryptLogoutNameID(logoutRequest *LogoutRequest, metadata *EntityDescriptor) error {
	encryptedID, _, err := idp.encryptLogoutIdentifier(logoutRequest.NameID, metadata)
	if err != nil || encryptedID == nil {
		return err
	}
	logoutRequest.EncryptedID = encryptedID
	logoutRequest.NameID = nil
	return nil
}

// encryptLogoutIdentifier returns a saml:EncryptedID holding nameID,
// encrypted to the encryption certificate in metadata, the service
// provider's metadata, and that certificate. If metadata has no encryption
// certificate, it returns nil, nil, nil.
func (idp *IdentityProvider) encryptLogoutIdentifier(nameID *NameID, metadata *EntityDescriptor) (*etree.Element, *x509.Certificate, error) {
	cert, methods, err := spEncryptionKey(metadata)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("service provider encryption certificate: %w", err)
	}
	encrypter := identifierEncrypter(idp.LogoutNameIDEncrypter, methods)
	if idp.LogoutNameIDEncrypter == nil && idp.LogoutNameIDEncrypterFunc != nil {
		if encrypter, err = idp.LogoutNameIDEncrypterFunc(slices.Clone(methods)); err != nil {
			return nil, nil, err
		}
	}
	encryptedID, err := encryptIdentifier(nameID.Element(), cert, encrypterWithRand(encrypter, idp.Rand))
	if err != nil {
		return nil, nil, fmt.Errorf("cannot encrypt NameID: %w", err)
	}
	return encryptedID, cert, nil
}

// spEncryptionKey returns the encryption certificate in metadata, a service
// provider's metadata, and the EncryptionMethods listed for it (see
// encryptionKey).
func spEncryptionKey(metadata *EntityDescriptor) (*x509.Certificate, []EncryptionMethod, error) {
	var keyDescriptors []KeyDescriptor
	for _, spssoDescriptor := range metadata.SPSSODescriptors {
		keyDescriptors = append(keyDescriptors, spssoDescriptor.KeyDescriptors...)
	}
	return encryptionKey(keyDescriptors)
}

// logoutRequestEndpoint returns the SingleLogoutService of a service
// provider to send a LogoutRequest to: the first HTTP-Redirect one, or else
// the first HTTP-POST one.
func logoutRequestEndpoint(metadata *EntityDescriptor) (*Endpoint, error) {
	for _, binding := range []string{HTTPRedirectBinding, HTTPPostBinding} {
		for _, spssoDescriptor := range metadata.SPSSODescriptors {
			for _, endpoint := range spssoDescriptor.SingleLogoutServices {
				if endpoint.Binding != binding {
					continue
				}
				if location, err := checkEndpointLocation(endpoint.Binding, endpoint.Location); err != nil || location == "" {
					continue
				}
				return &endpoint, nil
			}
		}
	}
	return nil, errors.New("the service provider metadata has no HTTP-Redirect or HTTP-POST SingleLogoutService endpoint")
}

// IdpLogoutRequestForm is what IdentityProvider.LogoutRequestFormTemplate is
// executed with: a signed LogoutRequest, base64 encoded, to be posted as
// the SAMLRequest field to URL with the HTTP-POST binding.
type IdpLogoutRequestForm struct {
	URL         string
	SAMLRequest string
}

// IdpLogoutComplete is what IdentityProvider.LogoutCompleteTemplate is
// executed with at the end of an IdP-initiated logout. Failed names the
// service providers that could not be logged out, if any.
type IdpLogoutComplete struct {
	Failed []string
}

var defaultLogoutRequestFormTemplate = template.Must(template.New("saml-logout-request-form").Parse(`` +
	`<html xmlns="http://www.w3.org/1999/xhtml">` +
	`<head><title>Continue</title></head>` +
	`<body>` +
	`<form method="post" action="{{.URL}}" id="SAMLRequestForm">` +
	`<input type="hidden" name="SAMLRequest" value="{{.SAMLRequest}}" />` +
	`<input id="SAMLSubmitButton" type="submit" value="Continue" />` +
	`</form>` +
	`<script>document.getElementById('SAMLSubmitButton').style.visibility='hidden';</script>` +
	`<script>document.getElementById('SAMLRequestForm').submit();</script>` +
	`</body>` +
	`</html>`))

// logoutRequestWriter signs logoutRequest for binding and returns a function
// that sends it to the browser, which cannot fail.
func (idp *IdentityProvider) logoutRequestWriter(logoutRequest *LogoutRequest, binding string) (func(http.ResponseWriter, *http.Request), error) {
	signingContext, err := idp.signingContext()
	if err != nil {
		return nil, err
	}
	switch binding {
	case HTTPRedirectBinding:
		encoded, err := deflateAndEncode(logoutRequest.Element())
		if err != nil {
			return nil, err
		}
		u, err := signedRedirectBindingURL(logoutRequest.Destination, redirectParamSAMLRequest, encoded, "", signingContext.GetSignatureMethodIdentifier(), signingContext)
		if err != nil {
			return nil, err
		}
		return func(w http.ResponseWriter, r *http.Request) {
			setNoCacheHeaders(w.Header())
			http.Redirect(w, r, u.String(), http.StatusFound) //nolint:gosec // the destination is the SingleLogoutService location from the SP metadata (http/https only)
		}, nil
	default: // HTTPPostBinding
		signed, err := signingContext.SignEnveloped(logoutRequest.Element())
		if err != nil {
			return nil, err
		}
		doc := etree.NewDocument()
		doc.SetRoot(signed)
		buf, err := doc.WriteToBytes()
		if err != nil {
			return nil, err
		}
		tmpl := idp.LogoutRequestFormTemplate
		if tmpl == nil {
			tmpl = defaultLogoutRequestFormTemplate
		}
		out := bytes.NewBuffer(nil)
		if err := tmpl.Execute(out, IdpLogoutRequestForm{
			URL:         logoutRequest.Destination,
			SAMLRequest: base64.StdEncoding.EncodeToString(buf),
		}); err != nil {
			return nil, err
		}
		return func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			setNoCacheHeaders(w.Header())
			_, _ = io.Copy(w, out)
		}, nil
	}
}

var defaultLogoutCompleteTemplate = template.Must(template.New("saml-logout-complete").Parse(`` +
	`<html xmlns="http://www.w3.org/1999/xhtml">` +
	`<head><title>Logged out</title></head>` +
	`<body>` +
	`<p>You have been logged out.</p>` +
	`{{if .Failed}}<p>The logout could not be confirmed by:</p><ul>{{range .Failed}}<li>{{.}}</li>{{end}}</ul>{{end}}` +
	`</body>` +
	`</html>`))

// finishLogout ends a single logout once every participant has been
// contacted: it answers the service provider that started it, with
// PartialLogout if some participant failed, or, for IdP-initiated logout,
// sends the browser to ReturnURL or shows that the user is logged out.
func (idp *IdentityProvider) finishLogout(w http.ResponseWriter, r *http.Request, state *logoutState) {
	idp.clearLogoutStateCookie(w, r)

	if in := state.Initiator; in != nil {
		endpoint := in.SLOEndpoint
		req := &IdpLogoutRequest{
			IDP:         idp,
			HTTPRequest: r,
			RelayState:  in.RelayState,
			Request:     LogoutRequest{ID: in.RequestID},
			SLOEndpoint: &endpoint,
			Now:         idp.now(),
		}
		if err := req.WriteLogoutResponse(w, makeLogoutResponseWithStatus(req, state.partial())); err != nil {
			idp.Logger.Printf("failed to write logout response to %s: %s", in.ServiceProviderID, err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
		return
	}

	failed := state.Failed
	if state.Dropped > 0 {
		failed = append(append([]string(nil), failed...), fmt.Sprintf("%d other services", state.Dropped))
	}
	if len(failed) > 0 {
		idp.Logger.Printf("single logout could not be confirmed by %s", strings.Join(failed, ", "))
	}
	if state.ReturnURL != "" {
		http.Redirect(w, r, state.ReturnURL, http.StatusFound) //nolint:gosec // ReturnURL is set by the application in StartLogout and carried in the signed state, never taken from the request
		return
	}
	tmpl := idp.LogoutCompleteTemplate
	if tmpl == nil {
		tmpl = defaultLogoutCompleteTemplate
	}
	out := bytes.NewBuffer(nil)
	if err := tmpl.Execute(out, IdpLogoutComplete{Failed: failed}); err != nil {
		idp.Logger.Printf("failed to write logout page: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if _, err := io.Copy(w, out); err != nil {
		idp.Logger.Printf("failed to write logout page: %s", err)
	}
}

// makeLogoutResponseWithStatus returns the LogoutResponse to req after the
// logout was propagated: StatusSuccess, with the second-level status
// StatusPartialLogout if partial is set (saml-core-2.0-os §3.7.3.2).
func makeLogoutResponseWithStatus(req *IdpLogoutRequest, partial bool) *LogoutResponse {
	resp := req.MakeLogoutResponse(StatusSuccess)
	if partial {
		resp.Status.StatusCode.StatusCode = &StatusCode{Value: StatusPartialLogout}
	}
	return resp
}

// isLogoutResponseMessage reports whether r carries a SAMLResponse, rather
// than a SAMLRequest, to the single logout service.
func isLogoutResponseMessage(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet:
		return r.URL.Query().Get(redirectParamSAMLResponse) != ""
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			return false
		}
		return r.PostForm.Get(redirectParamSAMLResponse) != ""
	}
	return false
}

// serveLogoutResponse handles a LogoutResponse sent by a service provider
// to which the IdP sent a LogoutRequest while propagating a logout, and
// continues the logout. A LogoutResponse that is not the answer to the
// outstanding LogoutRequest, or not validly signed by its service provider,
// is answered with HTTP 400 and leaves the logout where it was.
func (idp *IdentityProvider) serveLogoutResponse(w http.ResponseWriter, r *http.Request) {
	state, err := idp.readLogoutState(r)
	if err != nil {
		idp.Logger.Printf("failed to handle logout response: %s", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	resp, err := idp.validateLogoutResponse(r, state)
	if err != nil {
		idp.Logger.Printf("failed to validate logout response: %s", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	if resp.Status.StatusCode.Value != StatusSuccess {
		idp.Logger.Printf("logout response from %s has status %s", state.Current.ServiceProviderID, resp.Status.StatusCode.Value)
		state.Failed = append(state.Failed, state.Current.ServiceProviderID)
	}
	idp.continueLogout(w, r, state)
}

// validateLogoutResponse checks that the LogoutResponse r carries answers
// the outstanding LogoutRequest of state, and is signed by the service
// provider it was sent to.
func (idp *IdentityProvider) validateLogoutResponse(r *http.Request, state *logoutState) (*LogoutResponse, error) {
	if state.Current == nil || state.RequestID == "" {
		return nil, errors.New("no logout request is outstanding")
	}
	return idp.ValidateLogoutResponse(r, state.Current.ServiceProviderID, []string{state.RequestID})
}

// ValidateLogoutResponse checks the LogoutResponse that r carries to the
// single logout service, with the HTTP-Redirect, HTTP-POST or
// HTTP-POST-SimpleSign binding, from the service provider
// serviceProviderID, in answer to a LogoutRequest the IdP sent it through
// the browser (see MakeLogoutRequest). It is what ServeSLO does with the
// LogoutResponses of a logout it propagates, for an application that sends
// LogoutRequests itself.
//
// The response must be signed by the service provider, with a key of its
// metadata (looked up with ServiceProviderProvider) and an algorithm that
// RejectSHA1Signatures allows, and is read again from what an enveloped
// signature covers. Its Issuer must be serviceProviderID, its InResponseTo
// one of requestIDs, its Destination LogoutURL, and it must be recently
// issued. Its status is not checked.
func (idp *IdentityProvider) ValidateLogoutResponse(r *http.Request, serviceProviderID string, requestIDs []string) (*LogoutResponse, error) {
	if len(requestIDs) == 0 {
		return nil, errors.New("no logout request is outstanding")
	}
	buf, redirectMessage, simpleSign, err := readLogoutResponseMessage(r)
	if err != nil {
		return nil, err
	}
	if err := xmlroundtrip.Validate(buf); err != nil {
		return nil, fmt.Errorf("logout response contains invalid XML: %w", err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(buf); err != nil {
		return nil, fmt.Errorf("cannot parse logout response: %w", err)
	}
	if doc.Root() == nil {
		return nil, errors.New("cannot parse logout response: no root element")
	}
	var resp LogoutResponse
	if err := unmarshalElement(doc.Root(), &resp); err != nil {
		return nil, fmt.Errorf("cannot parse logout response: %w", err)
	}

	if resp.Issuer == nil || resp.Issuer.Value != serviceProviderID {
		return nil, fmt.Errorf("expected logout response issuer to be %q", serviceProviderID)
	}
	if idp.ServiceProviderProvider == nil {
		return nil, errors.New("IdentityProvider.ServiceProviderProvider is not set")
	}
	metadata, err := idp.ServiceProviderProvider.GetServiceProvider(r, serviceProviderID)
	if err != nil || metadata == nil {
		return nil, fmt.Errorf("cannot find service provider %s: %v", serviceProviderID, err)
	}
	certs, err := spSigningCerts(metadata)
	if err != nil {
		return nil, err
	}
	switch {
	case simpleSign != nil:
		err = checkSigAlgNotSHA1(idp.RejectSHA1Signatures, simpleSign.SigAlg)
	case redirectMessage != nil && redirectMessage.SignedContent != nil:
		err = checkSigAlgNotSHA1(idp.RejectSHA1Signatures, redirectMessage.SigAlg)
	default:
		err = checkEnvelopedSignatureNotSHA1(idp.RejectSHA1Signatures, doc.Root())
	}
	if err != nil {
		return nil, fmt.Errorf("logout response from %s: %w", serviceProviderID, err)
	}
	var signed *etree.Element
	switch {
	case simpleSign != nil:
		err = checkSPSimpleSignSignature(idp.RejectSHA1Signatures, simpleSign, metadata, idp.now())
	case redirectMessage != nil && redirectMessage.SignedContent != nil:
		err = checkRedirectBindingSignature(redirectMessage, func() ([]*x509.Certificate, error) { return certs, nil }, idp.now(), true)
	default:
		signed, err = verifiedEnvelopedElement(doc.Root(), certs, idp.dsigClock())
	}
	if err != nil {
		return nil, fmt.Errorf("cannot verify signature of logout response from %s: %w", serviceProviderID, err)
	}
	if signed != nil {
		// Read the response again from what the enveloped signature covers.
		// The issuer it names must be the one whose keys verified it.
		resp = LogoutResponse{}
		if err := unmarshalElement(signed, &resp); err != nil {
			return nil, fmt.Errorf("cannot parse logout response: %w", err)
		}
		if resp.Issuer == nil || resp.Issuer.Value != serviceProviderID {
			return nil, fmt.Errorf("signed logout response is not from %s", serviceProviderID)
		}
	}
	return &resp, idp.validateLogoutResponseFields(&resp, requestIDs)
}

// validateLogoutResponseFields checks the fields of an authenticated
// LogoutResponse that answers one of the LogoutRequests requestIDs, which
// were sent through the browser: its Destination must be LogoutURL.
func (idp *IdentityProvider) validateLogoutResponseFields(resp *LogoutResponse, requestIDs []string) error {
	if resp.InResponseTo == "" || !slices.Contains(requestIDs, resp.InResponseTo) {
		return fmt.Errorf("logout response InResponseTo %q does not match the outstanding request", resp.InResponseTo)
	}
	if err := validateLogoutResponseAnswer(resp, resp.InResponseTo, idp.now(), idp.limits()); err != nil {
		return err
	}
	if resp.Destination != idp.LogoutURL.String() {
		return fmt.Errorf("expected logout response destination to be %q, not %q", idp.LogoutURL.String(), resp.Destination)
	}
	return nil
}

// validateLogoutResponseAnswer checks the fields of an authenticated
// LogoutResponse, other than its Issuer and Destination, as an answer to the
// LogoutRequest requestID, at the time now, allowing the time limits l.
func validateLogoutResponseAnswer(resp *LogoutResponse, requestID string, now time.Time, l timeLimits) error {
	switch {
	case resp.InResponseTo != requestID:
		return fmt.Errorf("logout response InResponseTo %q does not match the outstanding request", resp.InResponseTo)
	case resp.Version != "2.0":
		return fmt.Errorf("expected SAML response version 2.0 got %v", resp.Version)
	case resp.IssueInstant.Add(l.delay()).Before(now):
		return fmt.Errorf("logout response expired at %s", resp.IssueInstant.Add(l.delay()))
	case resp.IssueInstant.Add(-l.skew()).After(now):
		return fmt.Errorf("logout response IssueInstant %s is in the future", resp.IssueInstant)
	}
	return nil
}

// readLogoutResponseMessage returns the XML of the LogoutResponse r carries,
// with the HTTP-Redirect binding (and then also the parsed query, whose
// signature the caller checks), the HTTP-POST-SimpleSign binding (and then
// also the SimpleSign message, whose signature the caller checks) or the
// HTTP-POST binding.
func readLogoutResponseMessage(r *http.Request) ([]byte, *redirectBindingMessage, *simpleSignMessage, error) {
	if r.Method == http.MethodGet {
		m, err := parseRedirectBindingQuery(r.URL.RawQuery, redirectParamSAMLResponse)
		if err != nil {
			return nil, nil, nil, err
		}
		compressed, err := base64.StdEncoding.DecodeString(m.Message)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("cannot decode response: %w", err)
		}
		buf, err := io.ReadAll(newSaferFlateReader(bytes.NewReader(compressed)))
		if err != nil {
			return nil, nil, nil, fmt.Errorf("cannot decompress response: %w", err)
		}
		return buf, m, nil, nil
	}
	simpleSign, err := parseSimpleSignRequest(r, redirectParamSAMLResponse)
	if err != nil {
		return nil, nil, nil, err
	}
	if simpleSign != nil {
		return simpleSign.XML, nil, simpleSign, nil
	}
	buf, err := base64.StdEncoding.DecodeString(r.PostForm.Get(redirectParamSAMLResponse))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("cannot decode response: %w", err)
	}
	return buf, nil, nil, nil
}

// logoutStateDeflatedPrefix starts the encoded logout state when its JSON
// is deflated. It is not in the base64url alphabet, so a state without it
// is plain JSON.
const logoutStateDeflatedPrefix = "z~"

// maxLogoutStateCookieValue is the longest logout state cookie value the
// IdP sets. Browsers drop a cookie whose name, value and attributes exceed
// about 4096 bytes, without telling the server.
const maxLogoutStateCookieValue = 3800

// logoutStateSignaturePrefix is prepended to the encoded state before it is
// signed, so that the signature cannot be mistaken for one over anything
// else the IdP signs.
const logoutStateSignaturePrefix = "saml-idp-logout-state\x00"

// logoutStateEncryptedPrefix starts the encoded logout state when it is
// encrypted with LogoutStateKey (see sealLogoutState). Like
// logoutStateDeflatedPrefix, it is not in the base64url alphabet.
const logoutStateEncryptedPrefix = "e~"

// logoutStateEncryptionVersion is the first byte of an encrypted logout
// state: the format, AES-256-GCM over the deflated JSON state.
const logoutStateEncryptionVersion = 1

// logoutStateEncryptionContext is the start of the additional data
// authenticated with an encrypted logout state, so that its ciphertext
// cannot be mistaken for anything else encrypted with the same key.
const logoutStateEncryptionContext = "saml-idp-logout-state-encryption\x00"

// logoutStateKeyIDLength is the length of the key ID in an encrypted
// logout state header.
const logoutStateKeyIDLength = 4

// logoutStateAEAD returns the AES-256-GCM AEAD keyed with LogoutStateKey,
// and the ID of that key: the start of a SHA-256 digest of it, which tells
// a state encrypted with another key from a corrupted one.
func (idp *IdentityProvider) logoutStateAEAD() (cipher.AEAD, []byte, error) {
	if len(idp.LogoutStateKey) != 32 {
		return nil, nil, fmt.Errorf("IdentityProvider.LogoutStateKey is %d bytes long, not 32", len(idp.LogoutStateKey))
	}
	block, err := aes.NewCipher(idp.LogoutStateKey)
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	keyDigest := sha256.Sum256(append([]byte("saml-idp-logout-state-key-id\x00"), idp.LogoutStateKey...))
	return aead, keyDigest[:logoutStateKeyIDLength], nil
}

// sealLogoutState encrypts plaintext, the deflated state, with
// LogoutStateKey. The result is a header (the version
// logoutStateEncryptionVersion and the key ID), a random nonce, and the
// ciphertext, which authenticates the header too.
func (idp *IdentityProvider) sealLogoutState(plaintext []byte) ([]byte, error) {
	aead, keyID, err := idp.logoutStateAEAD()
	if err != nil {
		return nil, err
	}
	header := append([]byte{logoutStateEncryptionVersion}, keyID...)
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(idp.randReader(), nonce); err != nil {
		return nil, err
	}
	sealed := append(append([]byte{}, header...), nonce...)
	return aead.Seal(sealed, nonce, plaintext, append([]byte(logoutStateEncryptionContext), header...)), nil
}

// openLogoutState decrypts sealed, made by sealLogoutState, and returns the
// deflated state.
func (idp *IdentityProvider) openLogoutState(sealed []byte) ([]byte, error) {
	if idp.LogoutStateKey == nil {
		return nil, errors.New("the logout state is encrypted, but IdentityProvider.LogoutStateKey is not set")
	}
	aead, keyID, err := idp.logoutStateAEAD()
	if err != nil {
		return nil, err
	}
	headerLength := 1 + logoutStateKeyIDLength
	if len(sealed) < headerLength+aead.NonceSize()+aead.Overhead() {
		return nil, errors.New("malformed logout state: too short")
	}
	header, rest := sealed[:headerLength], sealed[headerLength:]
	if header[0] != logoutStateEncryptionVersion {
		return nil, fmt.Errorf("malformed logout state: unknown version %d", header[0])
	}
	if !bytes.Equal(header[1:], keyID) {
		return nil, errors.New("the logout state was encrypted with another LogoutStateKey")
	}
	nonce, ciphertext := rest[:aead.NonceSize()], rest[aead.NonceSize():]
	plaintext, err := aead.Open(nil, nonce, ciphertext, append([]byte(logoutStateEncryptionContext), header...))
	if err != nil {
		return nil, fmt.Errorf("cannot decrypt logout state: %w", err)
	}
	return plaintext, nil
}

// logoutStateSigner returns the key the IdP signs with.
func (idp *IdentityProvider) logoutStateSigner() (crypto.Signer, error) {
	if !signerutil.IsNil(idp.Signer) {
		return idp.Signer, nil
	}
	if key, ok := idp.Key.(crypto.Signer); ok && !signerutil.IsNil(key) {
		return key, nil
	}
	return nil, errors.New("cannot sign: IdentityProvider.Key and IdentityProvider.Signer are both nil or invalid")
}

// encodeLogoutState serializes state, encrypts it if LogoutStateKey is set,
// and signs it with the IdP's key.
func (idp *IdentityProvider) encodeLogoutState(state *logoutState) (string, error) {
	signer, err := idp.logoutStateSigner()
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(state)
	if err != nil {
		return "", err
	}
	// The state is deflated: the participants' entity IDs and NameIDs (or
	// the markup of their EncryptedIDs) repeat a lot, and browsers drop
	// cookies over about 4 KB.
	var compressed bytes.Buffer
	fw, err := flate.NewWriter(&compressed, flate.BestCompression)
	if err != nil {
		return "", err
	}
	if _, err := fw.Write(payload); err != nil {
		return "", err
	}
	if err := fw.Close(); err != nil {
		return "", err
	}
	encoded := logoutStateDeflatedPrefix + base64.RawURLEncoding.EncodeToString(compressed.Bytes())
	if idp.LogoutStateKey != nil {
		sealed, err := idp.sealLogoutState(compressed.Bytes())
		if err != nil {
			return "", err
		}
		encoded = logoutStateEncryptedPrefix + base64.RawURLEncoding.EncodeToString(sealed)
	}
	digest := sha256.Sum256([]byte(logoutStateSignaturePrefix + encoded))
	signature, err := signer.Sign(idp.randReader(), digest[:], crypto.SHA256)
	if err != nil {
		return "", err
	}
	return encoded + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

// decodeLogoutState checks the signature of value, made by encodeLogoutState,
// and returns the state it holds if it has not expired.
func (idp *IdentityProvider) decodeLogoutState(value string) (*logoutState, error) {
	encoded, encodedSignature, ok := strings.Cut(value, ".")
	if !ok {
		return nil, errors.New("malformed logout state")
	}
	signature, err := base64.RawURLEncoding.DecodeString(encodedSignature)
	if err != nil {
		return nil, fmt.Errorf("malformed logout state: %w", err)
	}
	signer, err := idp.logoutStateSigner()
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(logoutStateSignaturePrefix + encoded))
	switch publicKey := signer.Public().(type) {
	case *rsa.PublicKey:
		err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], signature)
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(publicKey, digest[:], signature) {
			err = errors.New("ecdsa: verification error")
		}
	default:
		err = fmt.Errorf("unsupported key type %T", publicKey)
	}
	if err != nil {
		return nil, fmt.Errorf("invalid logout state signature: %w", err)
	}

	var payload []byte
	deflated := true
	switch {
	case strings.HasPrefix(encoded, logoutStateEncryptedPrefix):
		sealed, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(encoded, logoutStateEncryptedPrefix))
		if err != nil {
			return nil, fmt.Errorf("malformed logout state: %w", err)
		}
		if payload, err = idp.openLogoutState(sealed); err != nil {
			return nil, err
		}
	default:
		// A state written while LogoutStateKey was not set is signed, and
		// is read whether or not it is set now.
		deflated = strings.HasPrefix(encoded, logoutStateDeflatedPrefix)
		if payload, err = base64.RawURLEncoding.DecodeString(strings.TrimPrefix(encoded, logoutStateDeflatedPrefix)); err != nil {
			return nil, fmt.Errorf("malformed logout state: %w", err)
		}
	}
	if deflated {
		// A state written before the state was deflated has no prefix.
		if payload, err = io.ReadAll(newSaferFlateReader(bytes.NewReader(payload))); err != nil {
			return nil, fmt.Errorf("malformed logout state: %w", err)
		}
	}
	state := &logoutState{}
	if err := json.Unmarshal(payload, state); err != nil {
		return nil, fmt.Errorf("malformed logout state: %w", err)
	}
	if !idp.now().Before(state.Expires) {
		return nil, fmt.Errorf("logout state expired at %s", state.Expires)
	}
	return state, nil
}

// readLogoutState returns the state of the logout in progress, from its
// cookie.
func (idp *IdentityProvider) readLogoutState(r *http.Request) (*logoutState, error) {
	cookie, err := r.Cookie(logoutStateCookieName)
	if err != nil {
		return nil, errors.New("no single logout is in progress")
	}
	return idp.decodeLogoutState(cookie.Value)
}

// logoutStateCookie returns the cookie that holds the logout state, with
// value, scoped to LogoutURL. A LogoutResponse sent with the HTTP-POST
// binding arrives in a cross-site POST, so the cookie is SameSite=None when
// it can be Secure.
func (idp *IdentityProvider) logoutStateCookie(r *http.Request, value string, maxAge int) *http.Cookie {
	secure := idp.LogoutURL.Scheme == "https" || r.TLS != nil
	sameSite := http.SameSiteLaxMode
	if secure {
		sameSite = http.SameSiteNoneMode
	}
	path := idp.LogoutURL.Path
	if path == "" {
		path = "/"
	}
	return &http.Cookie{ //nolint:gosec // Secure is set whenever the IdP is served over https; SameSite=None is required for HTTP-POST LogoutResponses
		Name:     logoutStateCookieName,
		Value:    value,
		Path:     path,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   secure,
		SameSite: sameSite,
	}
}

// setLogoutStateCookie writes state to the logout state cookie.
//
// If EncryptLogoutNameID is set and LogoutStateKey is not, the NameIDs of
// the pending participants are first replaced with the EncryptedIDs their
// LogoutRequests will carry (see sealLogoutNameIDs). These take more room,
// so fewer participants then fit.
//
// A browser would silently drop a cookie that is too large, and the logout
// would then stop at the next LogoutResponse. So if the encoded state is
// longer than maxLogoutStateCookieValue, the last pending participants are
// given up on, and counted as not logged out (the logout ends with
// StatusPartialLogout), until it fits. If it does not fit even then, an
// error is returned.
func (idp *IdentityProvider) setLogoutStateCookie(w http.ResponseWriter, r *http.Request, state *logoutState) error {
	idp.sealLogoutNameIDs(r, state)
	value, err := idp.encodeLogoutState(state)
	if err != nil {
		return err
	}
	for len(value) > maxLogoutStateCookieValue && len(state.Pending) > 0 {
		dropped := state.Pending[len(state.Pending)-1]
		state.Pending = state.Pending[:len(state.Pending)-1]
		state.Dropped++
		idp.Logger.Printf("cannot propagate logout to %s: too many session participants to track in the logout state cookie", dropped.ServiceProviderID)
		if value, err = idp.encodeLogoutState(state); err != nil {
			return err
		}
	}
	if len(value) > maxLogoutStateCookieValue {
		return fmt.Errorf("the logout state is %d bytes, more than the %d a cookie can hold", len(value), maxLogoutStateCookieValue)
	}
	maxAge := int(state.Expires.Sub(idp.now()).Seconds()) + 1
	if maxAge < 1 {
		maxAge = 1
	}
	http.SetCookie(w, idp.logoutStateCookie(r, value, maxAge))
	return nil
}

func (idp *IdentityProvider) clearLogoutStateCookie(w http.ResponseWriter, r *http.Request) {
	if _, err := r.Cookie(logoutStateCookieName); err != nil {
		return
	}
	http.SetCookie(w, idp.logoutStateCookie(r, "", -1))
}
