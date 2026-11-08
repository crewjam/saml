package saml

import (
	"errors"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// spMustUnderstandEnvelope returns a SOAP Envelope around body whose Header
// holds an entry with the mustUnderstand value given, or none if it is "".
func spMustUnderstandEnvelope(body *etree.Element, mustUnderstand string) *etree.Element {
	env := etree.NewElement("soapenv:Envelope")
	env.CreateAttr("xmlns:soapenv", soapEnvelopeNamespace)
	header := env.CreateElement("soapenv:Header")
	entry := header.CreateElement("x:Extension")
	entry.CreateAttr("xmlns:x", "urn:example:extension")
	if mustUnderstand != "" {
		entry.CreateAttr("soapenv:mustUnderstand", mustUnderstand)
	}
	env.CreateElement("soapenv:Body").AddChild(body)
	return env
}

// SOAP 1.1 §4.2.3: a receiver that does not understand a header entry with
// mustUnderstand="1" must not process the message. The SP understands no
// SOAP header, so the SOAP responses it receives (ArtifactResponse, the
// Response to an attribute query, a SOAP LogoutResponse) with such an
// entry are refused. An entry with mustUnderstand="0", or none, is ignored.
func TestSPRefusesMandatorySOAPHeaderInResponses(t *testing.T) {
	t.Run("ArtifactResponse", func(t *testing.T) {
		e := spcovSetup(t)
		const artifactReqID = "id-artifact-request"
		parse := func(mustUnderstand string) error {
			el := e.artifactResponseEl(t, artifactReqID, true, nil)
			buf := spcovSerialize(t, spMustUnderstandEnvelope(el, mustUnderstand))
			_, err := e.sp.ParseXMLArtifactResponse(buf, []string{spcovRequestID}, artifactReqID, e.sp.AcsURL)
			return err
		}
		err := parse("1")
		assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), "cannot understand the mandatory SOAP header x:Extension"))
		assert.Check(t, errors.Is(err, ErrUnsupported), "%v", err)
		assert.NilError(t, parse("0"))
		assert.NilError(t, parse(""))
	})

	// soapBodyElement reads the Response to an attribute query, a SOAP
	// LogoutResponse, and the SOAP LogoutRequests both sides receive.
	t.Run("soapBodyElement", func(t *testing.T) {
		e := spcovSetup(t)
		for _, tag := range []string{"Response", "LogoutResponse"} {
			var body *etree.Element
			if tag == "Response" {
				body = e.response().Element()
			} else {
				body = e.logoutResponse().Element()
			}
			_, err := soapBodyElement(spcovSerialize(t, spMustUnderstandEnvelope(body.Copy(), "1")), tag)
			assert.Check(t, is.ErrorContains(err, "cannot understand the mandatory SOAP header x:Extension"), tag)
			el, err := soapBodyElement(spcovSerialize(t, spMustUnderstandEnvelope(body.Copy(), "0")), tag)
			assert.Check(t, err, tag)
			assert.Check(t, el != nil && el.Tag == tag, tag)
		}
	})
}
