package saml

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// This file implements the responder side of back-channel single logout at
// the IdP: a service provider sends a LogoutRequest to ServeSLO with the
// SAML SOAP binding (saml-bindings §3.2, saml-profiles §4.4.3.1 and
// §4.4.4.1), and gets the LogoutResponse in the HTTP response.

// soapFaultClient and soapFaultServer are the SOAP 1.1 fault codes for a
// message the sender got wrong and for a failure of the receiver (SOAP 1.1
// §4.4.1).
const (
	soapFaultClient = "Client"
	soapFaultServer = "Server"
)

// acceptsSOAPLogout reports whether ServeSLO accepts LogoutRequests with the
// SOAP binding: whether LogoutBindings, which the IdP metadata advertises,
// includes it.
func (idp *IdentityProvider) acceptsSOAPLogout() bool {
	return slices.Contains(idp.LogoutBindings, SOAPBinding)
}

// readSOAPLogoutRequest reads the body of r, at most MaxSOAPLogoutMessageSize
// bytes, as a SOAP 1.1 envelope, and returns the samlp:LogoutRequest its Body
// holds, serialized on its own with the namespace declarations it inherits.
func readSOAPLogoutRequest(r *http.Request) ([]byte, error) {
	body, err := readLimited(r.Body, MaxSOAPLogoutMessageSize)
	if err != nil {
		return nil, fmt.Errorf("SOAP logout request %w", err)
	}
	el, err := soapBodyElement(body, "LogoutRequest")
	if err != nil {
		return nil, fmt.Errorf("SOAP logout request: %w", err)
	}
	if err := checkNoMandatorySOAPHeader(el); err != nil {
		return nil, fmt.Errorf("SOAP logout request: %w", err)
	}
	return elementToBytes(el)
}

// checkNoMandatorySOAPHeader fails if the envelope that holds bodyChild has
// a header entry with mustUnderstand="1": the IdP understands none, so it
// must not process the message (SOAP 1.1 §4.2.3).
func checkNoMandatorySOAPHeader(bodyChild *etree.Element) error {
	body := bodyChild.Parent()
	if body == nil || body.Parent() == nil {
		return nil
	}
	header, err := findChild(body.Parent(), soapEnvelopeNamespace, "Header")
	if err != nil || header == nil {
		return err
	}
	for _, entry := range header.ChildElements() {
		for i := range entry.Attr {
			attr := &entry.Attr[i]
			if attr.Key == "mustUnderstand" && attr.NamespaceURI() == soapEnvelopeNamespace && attr.Value == "1" {
				return fmt.Errorf("cannot understand the mandatory SOAP header %s", entry.FullTag())
			}
		}
	}
	return nil
}

// serveSOAPLogoutRequest handles a LogoutRequest sent to ServeSLO with the
// SOAP binding. See ServeSLO.
func (idp *IdentityProvider) serveSOAPLogoutRequest(w http.ResponseWriter, r *http.Request) {
	req, err := NewIdpLogoutRequest(idp, r)
	if err != nil {
		idp.Logger.Printf("failed to parse SOAP logout request: %s", err)
		writeSOAPFault(w, soapFaultClient, "the logout request cannot be read")
		return
	}
	if err := req.Validate(); err != nil {
		idp.Logger.Printf("failed to validate SOAP logout request: %s", err)
		if !req.authenticated {
			writeSOAPFault(w, soapFaultClient, "the logout request is refused")
			return
		}
		// The service provider is known, so it is told what went wrong in a
		// LogoutResponse (saml-bindings §3.2.3.3).
		req.SLOEndpoint = &Endpoint{Binding: SOAPBinding}
		idp.writeSOAPLogoutResponse(w, req, req.MakeLogoutResponse(StatusRequester))
		return
	}

	// Find the other participants before the sessions are ended.
	participants, isParticipant, tracked, participantsErr := idp.sessionParticipantsOf(r, req.MatchesSession, req.ServiceProviderMetadata.EntityID)
	if participantsErr != nil {
		idp.Logger.Printf("cannot find the session participants to propagate logout request %s from %s to: %s",
			req.Request.ID, req.ServiceProviderMetadata.EntityID, participantsErr)
	}
	if !isParticipant {
		idp.refuseNonParticipantLogout(req)
		idp.writeSOAPLogoutResponse(w, req, req.MakeLogoutResponse(StatusRequester))
		return
	}
	if statusCode := idp.invalidateSession(w, r, req); statusCode != StatusSuccess {
		idp.writeSOAPLogoutResponse(w, req, req.MakeLogoutResponse(statusCode))
		return
	}
	failed := idp.logoutParticipantsSOAP(r, participants)
	partial := failed > 0 || idp.participantsUnknown(tracked, participantsErr)
	idp.writeSOAPLogoutResponse(w, req, makeLogoutResponseWithStatus(req, partial))
}

// BackChannelLogoutTimeout bounds how long ServeSLO spends logging the
// other session participants out over the SOAP binding when it answers a
// LogoutRequest that came over SOAP, so that it can answer before the
// service provider that sent it gives up. A participant that has not
// answered by then counts as not logged out (StatusPartialLogout). Each
// request is also bounded by the IdP's HTTPClient timeout.
var BackChannelLogoutTimeout = 15 * time.Second

// backChannelLogoutConcurrency is how many participants logoutParticipantsSOAP
// contacts at the same time.
const backChannelLogoutConcurrency = 8

// logoutParticipantsSOAP logs each of participants out over the SOAP binding
// (see logoutParticipantSOAP), several at a time and within
// BackChannelLogoutTimeout, and returns how many of them could not be
// logged out. Without a browser, a participant whose metadata lists no SOAP
// SingleLogoutService cannot be reached, and is one of them.
func (idp *IdentityProvider) logoutParticipantsSOAP(r *http.Request, participants []SessionParticipant) int {
	logFailure := func(participant SessionParticipant, err error) {
		if errors.Is(err, ErrNoSOAPLogoutEndpoint) {
			idp.Logger.Printf("cannot propagate a back-channel logout to %s: it has no SOAP SingleLogoutService", participant.ServiceProviderID)
			return
		}
		idp.Logger.Printf("back-channel logout of %s failed: %s", participant.ServiceProviderID, err)
	}

	// The LogoutRequests are made one at a time, as making them reads
	// the IdentityProvider's Rand; only sending them and waiting for the answers is done
	// concurrently.
	failed := 0
	var logouts []*soapLogout
	for _, participant := range participants {
		metadata, err := idp.participantMetadata(r, participant)
		var logout *soapLogout
		if err == nil {
			logout, err = idp.prepareSOAPLogout(metadata, participant, nil)
		}
		if err != nil {
			logFailure(participant, err)
			failed++
			continue
		}
		logouts = append(logouts, logout)
	}

	ctx, cancel := context.WithTimeout(r.Context(), BackChannelLogoutTimeout)
	defer cancel()
	errs := make([]error, len(logouts))
	var wg sync.WaitGroup
	sem := make(chan struct{}, backChannelLogoutConcurrency)
	for i, logout := range logouts {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			errs[i] = logout.send(ctx)
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			logFailure(logouts[i].participant, err)
			failed++
		}
	}
	return failed
}

// writeSOAPLogoutResponse signs resp and writes it as the SOAP answer to
// req, or a SOAP Server fault if that fails.
func (idp *IdentityProvider) writeSOAPLogoutResponse(w http.ResponseWriter, req *IdpLogoutRequest, resp *LogoutResponse) {
	if err := req.WriteLogoutResponse(w, resp); err != nil {
		idp.Logger.Printf("failed to write SOAP logout response: %s", err)
		writeSOAPFault(w, soapFaultServer, "the logout response cannot be made")
	}
}

// writeSOAPLogoutResponse writes resp, with an enveloped signature made with
// signingContext, in a SOAP envelope with HTTP status 200 (saml-bindings
// §3.2.3.3). It returns errors before it starts writing to w.
func writeSOAPLogoutResponse(w http.ResponseWriter, resp *LogoutResponse, signingContext *dsig.SigningContext) error {
	signed, err := signingContext.SignEnveloped(resp.Element())
	if err != nil {
		return err
	}
	buf, err := elementToBytes(soapEnvelope(signed))
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", soapContentType)
	setNoCacheHeaders(w.Header())
	_, err = w.Write(buf)
	return err
}

// writeSOAPFault writes a SOAP 1.1 Fault with code (soapFaultClient or
// soapFaultServer) and message, with HTTP status 500 (SOAP 1.1 §6.2).
func writeSOAPFault(w http.ResponseWriter, code, message string) {
	fault := etree.NewElement("soapenv:Fault")
	fault.CreateElement("faultcode").SetText("soapenv:" + code)
	fault.CreateElement("faultstring").SetText(message)
	buf, err := elementToBytes(soapEnvelope(fault))
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", soapContentType)
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = w.Write(buf)
}
