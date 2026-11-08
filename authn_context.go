package saml

// AuthnContextClass is a SAML authentication context class: a way the IdP
// authenticates the user (saml-authn-context-2.0-os §3.4). The constants
// are the classes the specification defines. An IdP may define its own,
// such as "http://schemas.microsoft.com/claims/multipleauthn".
type AuthnContextClass string

// The authentication context classes of saml-authn-context-2.0-os §3.4.
//
//nolint:gosec // G101: authentication context class URIs, not credentials
const (
	AuthnContextInternetProtocol            AuthnContextClass = "urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocol"
	AuthnContextInternetProtocolPassword    AuthnContextClass = "urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocolPassword"
	AuthnContextKerberos                    AuthnContextClass = "urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos"
	AuthnContextMobileOneFactorUnregistered AuthnContextClass = "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileOneFactorUnregistered"
	AuthnContextMobileTwoFactorUnregistered AuthnContextClass = "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorUnregistered"
	AuthnContextMobileOneFactorContract     AuthnContextClass = "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileOneFactorContract"
	AuthnContextMobileTwoFactorContract     AuthnContextClass = "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract"
	AuthnContextPassword                    AuthnContextClass = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"
	AuthnContextPasswordProtectedTransport  AuthnContextClass = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
	AuthnContextPreviousSession             AuthnContextClass = "urn:oasis:names:tc:SAML:2.0:ac:classes:PreviousSession"
	AuthnContextX509                        AuthnContextClass = "urn:oasis:names:tc:SAML:2.0:ac:classes:X509"
	AuthnContextPGP                         AuthnContextClass = "urn:oasis:names:tc:SAML:2.0:ac:classes:PGP"
	AuthnContextSPKI                        AuthnContextClass = "urn:oasis:names:tc:SAML:2.0:ac:classes:SPKI"
	AuthnContextXMLDSig                     AuthnContextClass = "urn:oasis:names:tc:SAML:2.0:ac:classes:XMLDSig"
	AuthnContextSmartcard                   AuthnContextClass = "urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard"
	AuthnContextSmartcardPKI                AuthnContextClass = "urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI"
	AuthnContextSoftwarePKI                 AuthnContextClass = "urn:oasis:names:tc:SAML:2.0:ac:classes:SoftwarePKI"
	AuthnContextTelephony                   AuthnContextClass = "urn:oasis:names:tc:SAML:2.0:ac:classes:Telephony"
	AuthnContextNomadTelephony              AuthnContextClass = "urn:oasis:names:tc:SAML:2.0:ac:classes:NomadTelephony"
	AuthnContextPersonalTelephony           AuthnContextClass = "urn:oasis:names:tc:SAML:2.0:ac:classes:PersonalTelephony"
	AuthnContextAuthenticatedTelephony      AuthnContextClass = "urn:oasis:names:tc:SAML:2.0:ac:classes:AuthenticatedTelephony"
	AuthnContextSecureRemotePassword        AuthnContextClass = "urn:oasis:names:tc:SAML:2.0:ac:classes:SecureRemotePassword"
	AuthnContextTLSClient                   AuthnContextClass = "urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient"
	AuthnContextTimeSyncToken               AuthnContextClass = "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken"
	AuthnContextUnspecified                 AuthnContextClass = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified"
)

// AuthnContextComparison says how the IdP compares the authentication
// context classes of a RequestedAuthnContext with the one it uses
// (saml-core §3.3.2.2.1).
type AuthnContextComparison string

const (
	// AuthnContextComparisonExact requires one of the classes exactly.
	AuthnContextComparisonExact AuthnContextComparison = "exact"
	// AuthnContextComparisonMinimum requires a class at least as strong as one of the
	// classes.
	AuthnContextComparisonMinimum AuthnContextComparison = "minimum"
	// AuthnContextComparisonMaximum requires a class as strong as possible, but no
	// stronger than one of the classes.
	AuthnContextComparisonMaximum AuthnContextComparison = "maximum"
	// AuthnContextComparisonBetter requires a class stronger than all of the classes.
	AuthnContextComparisonBetter AuthnContextComparison = "better"
)
