// Package attrname defines the names of commonly used SAML attributes, so
// that code reading or writing them does not have to spell out OIDs and URIs:
//
//	email := assertion.Attributes.Get(attrname.Mail)
//
// An attribute is identified by its Name, not its FriendlyName, and the IdP
// decides which names it sends:
//
//   - Shibboleth, SimpleSAMLphp, research and education federations, and
//     this module's IdP follow the SAML V2.0 X.500/LDAP attribute profile and
//     send urn:oid: names, such as Mail, with the NameFormat FormatURI.
//   - Keycloak's built-in mappers send urn:oid: names too, but its "X500
//     email" mapper uses EmailAddress (the PKCS #9 OID), not Mail.
//   - Microsoft Entra ID and AD FS send WS-Federation claim URIs, such as
//     ClaimEmailAddress, and Entra adds its own, such as EntraObjectID.
//   - Okta, Google Workspace, OneLogin and most other IdPs send whatever names
//     the administrator types in, usually plain names such as "email" with
//     the NameFormat FormatBasic or FormatUnspecified. No constant can
//     predict those: agree on the names with the IdP administrator.
//
// So an application that accepts several IdPs may have to look for more than
// one name. The constants are untyped strings, so they work wherever a name is
// a string. Go struct tags cannot refer to constants, so a tag such as
// `saml:"urn:oid:0.9.2342.19200300.100.1.3"` still spells out the name.
package attrname

// Attribute NameFormats (SAML 2.0 core, section 8.2).
const (
	// FormatURI is the NameFormat of attributes whose Name is a URI, such as
	// the urn:oid: names in this package.
	FormatURI = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"

	// FormatBasic is the NameFormat of attributes whose Name is a plain
	// string, such as "mail".
	FormatBasic = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"

	// FormatUnspecified is the NameFormat that leaves the interpretation of
	// the Name to the parties. It is the default when NameFormat is absent.
	FormatUnspecified = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"
)

// LDAP attributes (RFC 4519, RFC 4524, RFC 2798 inetOrgPerson), named per
// the SAML V2.0 X.500/LDAP attribute profile. The comment gives the LDAP
// name, which IdPs usually send as the FriendlyName.
const (
	UID                   = "urn:oid:0.9.2342.19200300.100.1.1"  // uid
	Mail                  = "urn:oid:0.9.2342.19200300.100.1.3"  // mail
	Mobile                = "urn:oid:0.9.2342.19200300.100.1.41" // mobile
	CommonName            = "urn:oid:2.5.4.3"                    // cn
	Surname               = "urn:oid:2.5.4.4"                    // sn
	TelephoneNumber       = "urn:oid:2.5.4.20"                   // telephoneNumber
	Title                 = "urn:oid:2.5.4.12"                   // title
	OrganizationName      = "urn:oid:2.5.4.10"                   // o
	OrganizationalUnit    = "urn:oid:2.5.4.11"                   // ou
	GivenName             = "urn:oid:2.5.4.42"                   // givenName
	DisplayName           = "urn:oid:2.16.840.1.113730.3.1.241"  // displayName
	EmployeeNumber        = "urn:oid:2.16.840.1.113730.3.1.3"    // employeeNumber
	PreferredLanguage     = "urn:oid:2.16.840.1.113730.3.1.39"   // preferredLanguage
	SchacHomeOrganization = "urn:oid:1.3.6.1.4.1.25178.1.2.9"    // schacHomeOrganization
)

// eduPerson attributes (https://refeds.org/eduperson), common in research
// and education federations.
const (
	EduPersonAffiliation        = "urn:oid:1.3.6.1.4.1.5923.1.1.1.1"  // eduPersonAffiliation
	EduPersonNickname           = "urn:oid:1.3.6.1.4.1.5923.1.1.1.2"  // eduPersonNickname
	EduPersonOrgDN              = "urn:oid:1.3.6.1.4.1.5923.1.1.1.3"  // eduPersonOrgDN
	EduPersonOrgUnitDN          = "urn:oid:1.3.6.1.4.1.5923.1.1.1.4"  // eduPersonOrgUnitDN
	EduPersonPrimaryAffiliation = "urn:oid:1.3.6.1.4.1.5923.1.1.1.5"  // eduPersonPrimaryAffiliation
	EduPersonPrincipalName      = "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"  // eduPersonPrincipalName
	EduPersonEntitlement        = "urn:oid:1.3.6.1.4.1.5923.1.1.1.7"  // eduPersonEntitlement
	EduPersonPrimaryOrgUnitDN   = "urn:oid:1.3.6.1.4.1.5923.1.1.1.8"  // eduPersonPrimaryOrgUnitDN
	EduPersonScopedAffiliation  = "urn:oid:1.3.6.1.4.1.5923.1.1.1.9"  // eduPersonScopedAffiliation
	EduPersonTargetedID         = "urn:oid:1.3.6.1.4.1.5923.1.1.1.10" // eduPersonTargetedID (deprecated; use PairwiseID)
	EduPersonAssurance          = "urn:oid:1.3.6.1.4.1.5923.1.1.1.11" // eduPersonAssurance
	EduPersonUniqueID           = "urn:oid:1.3.6.1.4.1.5923.1.1.1.13" // eduPersonUniqueId
	EduPersonOrcid              = "urn:oid:1.3.6.1.4.1.5923.1.1.1.16" // eduPersonOrcid
)

// Subject identifier attributes (SAML V2.0 Subject Identifier Attributes
// Profile), the successors of persistent NameIDs and eduPersonTargetedID.
const (
	// SubjectID is a long-lived identifier of the subject, the same for every
	// service provider, of the form "value@scope".
	SubjectID = "urn:oasis:names:tc:SAML:attribute:subject-id"

	// PairwiseID is a long-lived identifier of the subject that differs for
	// each service provider, of the form "value@scope".
	PairwiseID = "urn:oasis:names:tc:SAML:attribute:pairwise-id"
)

// WS-Federation claim types (as defined by .NET's ClaimTypes), sent as
// attribute Names by Microsoft Entra ID and AD FS, and by IdPs configured to
// imitate them. An Entra ID enterprise application gets ClaimName (the UPN),
// ClaimEmailAddress, ClaimGivenName and ClaimSurname by default.
const (
	ClaimEmailAddress       = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
	ClaimGivenName          = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"
	ClaimSurname            = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"
	ClaimName               = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
	ClaimNameIdentifier     = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier"
	ClaimUPN                = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"
	ClaimGroups             = "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"
	ClaimRole               = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"
	ClaimWindowsAccountName = "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname"
	ClaimPrimarySID         = "http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid"

	// ClaimCommonName and ClaimGroup are AD FS claims; note that ClaimGroup
	// is not ClaimGroups.
	ClaimCommonName = "http://schemas.xmlsoap.org/claims/CommonName"
	ClaimGroup      = "http://schemas.xmlsoap.org/claims/Group"
)

// Claims specific to Microsoft Entra ID.
const (
	// EntraTenantID is the ID of the user's directory (tenant). A
	// multi-tenant application must check it as well as EntraObjectID.
	EntraTenantID = "http://schemas.microsoft.com/identity/claims/tenantid"

	// EntraObjectID is the immutable ID of the user within the tenant.
	EntraObjectID = "http://schemas.microsoft.com/identity/claims/objectidentifier"

	EntraDisplayName      = "http://schemas.microsoft.com/identity/claims/displayname"
	EntraIdentityProvider = "http://schemas.microsoft.com/identity/claims/identityprovider"
	EntraAuthnMethods     = "http://schemas.microsoft.com/claims/authnmethodsreferences"

	// EntraDirectoryRoles (wids) lists the IDs of the tenant-wide roles the
	// user holds, such as Global Administrator.
	EntraDirectoryRoles = "http://schemas.microsoft.com/ws/2008/06/identity/claims/wids"

	// EntraGroupsLink replaces ClaimGroups when the user is in more groups
	// than fit in the token (150 for SAML). Its value is a Graph URL from
	// which to fetch them.
	EntraGroupsLink = "http://schemas.microsoft.com/claims/groups.link"
)
