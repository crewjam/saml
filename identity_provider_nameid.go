package saml

import "fmt"

const (
	// encryptedNameIDFormat is the format an AuthnRequest's NameIDPolicy
	// names to ask for an encrypted identifier (saml-core §8.3.9). It places
	// no constraint on the format of the NameID itself.
	encryptedNameIDFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted"

	// entityNameIDFormat is the entity identifier format (saml-core §8.3.6).
	entityNameIDFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
)

// makeAssertionNameID returns the NameID that DefaultAssertionMaker puts in
// the Subject of the assertion it makes for session.
//
// The format is session.NameIDFormat, or transient if it is empty, as
// before. NameQualifier and SPNameQualifier are only set for the persistent
// and transient formats, the only ones that define them (saml-core §2.2.2,
// §8.3.7, §8.3.8). When req.IDP.EnforceNameIDPolicy is set, the request's
// NameIDPolicy is also enforced (see checkNameIDPolicy).
func (req *IdpAuthnRequest) makeAssertionNameID(session *Session) (*NameID, error) {
	format := session.NameIDFormat
	if format == "" {
		format = string(TransientNameIDFormat)
	}
	nameID := &NameID{Format: format, Value: session.NameID}

	spNameQualifier := ""
	if req.ServiceProviderMetadata != nil {
		spNameQualifier = req.ServiceProviderMetadata.EntityID
	}
	if req.IDP.EnforceNameIDPolicy {
		requested, err := req.checkNameIDPolicy(format)
		if err != nil {
			return nil, err
		}
		if requested != "" {
			spNameQualifier = requested
			// saml-core §3.4.1.1 requires the requested SPNameQualifier
			// in the NameID, whatever its format, except the entity
			// format, for which it MUST be omitted (§8.3.6).
			if format != entityNameIDFormat {
				nameID.SPNameQualifier = requested
			}
		}
	}

	if nameIDFormatDefinesQualifiers(format) {
		nameID.NameQualifier = req.IDP.Metadata().EntityID
		nameID.SPNameQualifier = spNameQualifier
	}
	return nameID, nil
}

// nameIDFormatDefinesQualifiers reports whether format defines the use of
// the NameQualifier and SPNameQualifier attributes. saml-core §2.2.2 says
// they SHOULD be omitted for the others.
func nameIDFormatDefinesQualifiers(format string) bool {
	return format == string(PersistentNameIDFormat) || format == string(TransientNameIDFormat)
}

// checkNameIDPolicy checks the request's NameIDPolicy against a NameID of
// the given format, as saml-core §3.4.1.1 requires: a Format other than
// unspecified or encrypted must be the one issued. It returns the
// SPNameQualifier the policy asks for, if any, or a *StatusError with
// Requester and InvalidNameIDPolicy if the policy cannot be satisfied.
func (req *IdpAuthnRequest) checkNameIDPolicy(format string) (string, error) {
	policy := req.Request.NameIDPolicy
	if policy == nil {
		return "", nil
	}
	if policy.Format != nil {
		switch requested := *policy.Format; requested {
		case "", string(UnspecifiedNameIDFormat), encryptedNameIDFormat, format:
		default:
			return "", &StatusError{
				TopLevel:    StatusRequester,
				SecondLevel: StatusInvalidNameIDPolicy,
				Message:     fmt.Sprintf("the name identifier format %s is not supported", requested),
			}
		}
	}
	if policy.SPNameQualifier == nil {
		return "", nil
	}
	return *policy.SPNameQualifier, nil
}
