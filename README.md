# SAML

[![](https://godoc.org/github.com/crewjam/saml?status.svg)](http://godoc.org/github.com/crewjam/saml)

![Build Status](https://github.com/crewjam/saml/actions/workflows/test.yml/badge.svg)

Package saml contains a partial implementation of the SAML standard in golang.
SAML is a standard for identity federation, i.e. either allowing a third party to authenticate your users or allowing third parties to rely on us to authenticate their users.

## Introduction

In SAML parlance an **Identity Provider** (IDP) is a service that knows how to authenticate users. A **Service Provider** (SP) is a service that delegates authentication to an IDP. If you are building a service where users log in with someone else's credentials, then you are a **Service Provider**. This package supports implementing both service providers and identity providers.

The core package contains the implementation of SAML. Service providers should use the package x/samlsp, with x/samlsp/slo for single logout (see [Getting Started as a Service Provider](#getting-started-as-a-service-provider)). The older package samlsp provides middleware that also keeps sessions; it remains for existing applications. Identity providers built into an existing application can use the experimental package x/samlidp, which verifies AuthnRequests and makes signed Responses while the application keeps its own users, sessions and login pages, with x/samlidp/idpslo for single logout and x/samlidp/idpartifact for the HTTP-Artifact binding. The package samlidp provides a rudimentary IDP service that is useful for testing or as a starting point for other integrations.

## Getting Started as a Service Provider

New service providers should use `github.com/crewjam/saml/x/samlsp`. It implements the SAML Web Browser SSO profile: it builds requests, verifies responses and serves the SP metadata, and the application keeps its own sessions. It lives under `x/` while its API settles.

Each service provider must have an self-signed X.509 key pair established. You can generate your own with something like this:

    openssl req -x509 -newkey rsa:2048 -keyout myservice.key -out myservice.cert -days 365 -nodes -subj "/CN=myservice.example.com"

We also need an identity provider. In our case, we'll use [samltest.dev](https://www.samltest.dev/), an identity provider designed for testing.

samltest.dev gives each app its own IDP, so first create an app with at least one test user. You can do this on the website or with the [API](https://www.samltest.dev/#api):

    curl -X POST https://www.samltest.dev/api/apps \
      -H "Content-Type: application/json" \
      -d '{"users":[{"email":"john@example.com","firstName":"John","lastName":"Doe"}]}'

The response contains the app's ID (for example `app_01kg2nmcmp9gey67b0kxpqm643`). The IDP metadata URL for the app is `https://www.samltest.dev/apps/<APP_ID>/metadata`. Download it once and keep it with the service:

    curl -o idp-metadata.xml https://www.samltest.dev/apps/<APP_ID>/metadata

The IDP metadata names the certificates the service provider trusts to sign assertions, so whoever controls it controls who can log in. Loading it from a file you checked, rather than fetching it at every start, pins the IDP. See [Trusting the IDP's metadata](#trusting-the-idps-metadata) for the alternatives.

```golang
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/crewjam/saml/x/samlsp"
	"github.com/crewjam/saml/x/samlsp/pending"
)

var (
	config  *samlsp.Config
	tracker *pending.Tracker
)

func main() {
	keyPair, err := tls.LoadX509KeyPair("myservice.cert", "myservice.key")
	if err != nil {
		log.Fatal(err)
	}
	cert, err := x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		log.Fatal(err)
	}
	key := keyPair.PrivateKey.(*rsa.PrivateKey)

	idpMetadata, err := os.ReadFile("idp-metadata.xml")
	if err != nil {
		log.Fatal(err)
	}

	entityID := "http://localhost:8000/saml/metadata" // the ACS is beside it, at /saml/acs
	config, err = samlsp.New(entityID, samlsp.StaticMetadataBytes(idpMetadata),
		samlsp.WithSigningKey(key, cert),
		samlsp.WithEncryptionKey(key, cert)) // so that the IDP can encrypt assertions
	if err != nil {
		log.Fatal(err)
	}
	// Remembers each login in progress in a cookie, authenticated with
	// this key: 32 or more random bytes, the same on every server.
	tracker, err = pending.New(config, []byte(os.Getenv("SAML_COOKIE_KEY")))
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc(config.MetadataPath(), config.ServeMetadata)
	http.HandleFunc(config.ACSPath(), acs)
	http.HandleFunc("/login", login)
	log.Fatal(http.ListenAndServe("localhost:8000", nil))
}

// login sends the browser to the IDP with an AuthnRequest, and remembers
// the request's ID in this browser until the IDP answers.
func login(w http.ResponseWriter, r *http.Request) {
	msg, err := config.AuthnRequest(r.Context(), rand.Text())
	if err == nil {
		err = tracker.Remember(w, msg, "")
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	msg.Write(w)
}

// acs verifies the IDP's Response to the request this browser started.
func acs(w http.ResponseWriter, r *http.Request) {
	login, err := tracker.Take(w, r)
	if err != nil {
		http.Error(w, "no login in progress", http.StatusForbidden)
		return
	}
	assertion, err := config.ParseResponse(r.Context(), r, samlsp.WithRequestID(login.ID))
	if err != nil {
		http.Error(w, "login failed", http.StatusForbidden)
		return
	}
	// Start the application's own session here.
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "Hello, %s!\n", assertion.Subject)
}
```

Login has two steps. `/login` sends the browser to the IDP with an `AuthnRequest`, and `x/samlsp/pending` remembers the request's ID in a cookie, found again by the RelayState. The ACS checks that the Response answers that request, so a Response is accepted only in the browser that asked for it. The cookie is authenticated with `SAML_COOKIE_KEY`, and over `https` it is `Secure` and `SameSite=None`, since the IDP's POST to the ACS is a cross-site request. `example/trivial` is a complete version of this program, with sessions and single logout.

Next we'll have to register our service provider with the identity provider to establish trust from the service provider to the IDP. samltest.dev doesn't take an uploaded metadata file. Instead, set the app's SP ACS URL and SP Entity ID, either under "SAML SP Settings" on `https://www.samltest.dev/apps/<APP_ID>` or with the API:

    curl -X PUT https://www.samltest.dev/api/apps/<APP_ID> \
      -H "Content-Type: application/json" \
      -d '{"users":[{"email":"john@example.com","firstName":"John","lastName":"Doe"}],
           "spAcsUrl":"http://localhost:8000/saml/acs",
           "spEntityId":"http://localhost:8000/saml/metadata"}'

The entity ID is conventionally the URL of the SP metadata, and the ACS is beside it unless `WithACSURL` says otherwise. `MetadataPath` and `ACSPath` give the paths to serve them at. You can view the service provider's metadata at `localhost:8000/saml/metadata`.

Now you should be able to authenticate. The flow should look like this:

1. You browse to `localhost:8000/login`.

1. You are redirected to `https://www.samltest.dev/apps/<APP_ID>/login`.

1. samltest.dev asks which of the app's test users you want to log in as. There is no password.

1. samltest.dev returns you an HTML document which contains an HTML form setup to POST to `localhost:8000/saml/acs`. The form is automatically submitted if you have javascript enabled.

1. The service verifies the Response and greets you by your NameID. A real application starts its session there and redirects to the page the user asked for.

By default the service provider turns on the checks that `saml.ServiceProvider` leaves off for compatibility, and refuses replayed assertions. See [Hardening](#hardening) for what they are and how to relax one for an IDP that needs it.

### Reading the user's name, email and other attributes

`ParseResponse` returns a verified `Assertion`. Its `NameID` (and `Subject`, the NameID's value) identifies the user, and its `Attributes` are what the IDP says about them:

```golang
// The first value of an attribute, or "" if it is missing.
// Common attribute names are constants in github.com/crewjam/saml/attrname.
email := assertion.Attributes.Get(attrname.Mail)

// Every attribute, with all of its values.
for _, attribute := range assertion.Attributes {
	fmt.Println(attribute.Name, attribute.Values)
}

// Or decode them into a struct, by attribute Name.
var user struct {
	Email   string    `saml:"urn:oid:0.9.2342.19200300.100.1.3"`
	Groups  []string  `saml:"http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"`
	Created time.Time `saml:"urn:example:created"`
}
if err := assertion.DecodeAttributes(&user); err != nil {
	return err
}
```

Attributes are looked up by their `Name`, never by `FriendlyName`, which is only a hint for people. The IDP decides which attributes it sends and what they are called, so if one you expect is missing, check the IDP's attribute release settings; listing every attribute as above shows exactly what you received. `DecodeAttributes` parses values by the XML Schema rules into strings, bools, numbers, times, durations, bytes and URLs, and calls `UnmarshalSAMLAttribute` or `UnmarshalText` on types that have them.

Attributes the IDP encrypts (`EncryptedAttribute`) are decrypted with the key of `WithEncryptionKey`, like an encrypted assertion, and read like the others. An assertion whose Subject identifies the user with a `BaseID` rather than a NameID is refused unless the Config is made with `samlsp.AcceptBaseID`; `Assertion.BaseID` then holds the element, which your code must interpret.

### Logging out

Single logout is in `github.com/crewjam/saml/x/samlsp/slo`. Configure the SP's SLO endpoint when making the Config, and keep the NameID and session indexes of each login:

```golang
config, err := samlsp.New(entityID, idp,
	samlsp.WithSigningKey(key, cert), // logout messages are signed
	slo.Endpoint("http://localhost:8000/saml/slo"))
logout, err := slo.New(config)
http.HandleFunc(logout.Path(), sloHandler)

// To log a user out: end the local session first, then tell the IDP.
msg, err := logout.Request(ctx, session.NameID, rand.Text(), slo.WithSessionIndex(session.SessionIndexes...))
// remember msg.ID in this browser, for ParseResponse
msg.Write(w)
```

The IDP's answer, a `LogoutResponse`, arrives at the SLO URL, where `logout.ParseResponse` verifies it. So do `LogoutRequest`s the IDP sends when the user logs out elsewhere: `logout.ParseRequest` verifies them, the application ends the sessions they name, and `logout.Response` answers. `slo.IsRequest` and `slo.IsResponse` tell the two apart. The SAML single logout profile requires logout messages sent with the HTTP-Redirect or HTTP-POST binding to be signed, and many IDPs enforce it, so give the Config a signing key. With `slo.BackChannel`, logout messages are also exchanged server to server with the SOAP binding. `example/trivial` shows the whole flow.

### Trusting the IDP's metadata

The service provider trusts whatever signing certificates the IDP metadata names, so get the metadata from a source you trust. The first argument of `samlsp.New` is a function that supplies it:

- **A file kept with the service**, as above, with `samlsp.StaticMetadataBytes`, checked when you download it and updated when the IDP rotates its keys.

- **Signed metadata.** If the IDP (or its federation) signs its metadata, fetch it and check the signature against the metadata signing certificate, obtained out of band:

  ```golang
  idp := samlsp.RemoteMetadata("https://idp.example.com/metadata",
  	samlsp.WithMetadataSigners(idpMetadataSigningCert))
  ```

  Only what the signature covers is parsed. An IDP served by this package signs its metadata when `IdentityProvider.SignMetadata` is set.

- **An `https` URL you trust**, with `samlsp.RemoteMetadata` alone. The metadata is then only as trustworthy as that server and its TLS certificate, and a plain `http` URL can be changed by anyone on the network path.

`RemoteMetadata` caches the metadata and refreshes it in the background, at least hourly (`WithRefreshInterval`) and sooner if its `cacheDuration` or `validUntil` says so, which picks up rotated keys. Federation metadata (an `<EntitiesDescriptor>` such as eduGAIN or InCommon publishes) holds many IDPs: choose one with `WithIdentityProviderEntityID`, or fetch only its entry from the federation's Metadata Query service with `samlsp.MDQMetadata`. Any function of your own works too, for example one that picks the IDP of the tenant named in the request's context.

### Metadata validity and refresh

The metadata parsing functions record when the document was retrieved. When an entity is selected from nested federation metadata, the parser also applies every enclosing `<EntitiesDescriptor>` policy. `validUntil` is a hard validity bound; `cacheDuration` schedules refresh and does not by itself invalidate a cached copy after a refresh failure, as clarified by [OASIS SAML v2.0 Errata 05](https://docs.oasis-open.org/security/saml/v2.0/errata05/csd01/saml-v2.0-errata05-csd01.html). `MetadataProvider` rejects metadata whose effective `validUntil` has passed.

Use `MetadataProvider` when metadata comes from a URL and the application needs to refresh it over time:

```go
metadataProvider := samlsp.NewMetadataProvider(http.DefaultClient, metadataURL, idpEntityID)
middleware, err := samlsp.New(samlsp.Options{
	URL:                 *rootURL,
	Key:                 keyPair.PrivateKey.(*rsa.PrivateKey),
	Certificate:         keyPair.Leaf,
	IDPMetadataProvider: metadataProvider,
})
if err != nil {
	return err
}
```

For a feed that signs its metadata, use `NewSignedMetadataProvider` and provide the metadata-signing certificates from a trusted source.

`Metadata` fetches on first use and checks for refresh when called again. It refreshes before the current entity's effective `cacheDuration` or `validUntil` deadline. `samlsp.Middleware` calls the provider before each authentication, ACS and SLO operation and uses a request-local service-provider copy, so a refresh does not change configuration seen by concurrent requests. The provider does not start a background goroutine. If a fetch fails, it returns the last document while its `validUntil` bound remains valid; a `cacheDuration` deadline alone does not invalidate cached metadata. After hard expiry, the error is returned and the service provider must not continue using the old keys or endpoints. The returned metadata is shared and must be treated as read-only.

Applications that obtain metadata through a custom `ServiceProviderProvider` can calculate a refresh deadline with `EntityDescriptor.MetadataRefreshAt(retrievedAt)`, passing the time they retrieved the document. `cacheDuration` deadlines are relative to that time.

### Querying attributes from the IDP

An IDP that is also a SAML attribute authority (for example Shibboleth) can be asked for a user's attributes outside of a login, with an `AttributeQuery` sent over the SOAP back channel (the Assertion Query/Request profile). This needs an `AttributeAuthorityDescriptor` with a SOAP `AttributeService` in the IDP metadata, and the IDP must be willing to answer this service provider:

```golang
// The NameID the IDP issued for the user, as received at login, so that its
// Format and qualifiers match what the IDP knows the user by.
attributes, err := config.QueryAttributes(ctx, assertion.NameID,
	samlsp.WithQueriedAttributes(attrname.Mail))
if err != nil {
	return err
}
fmt.Println(attributes.Get(attrname.Mail))
```

Leave out `WithQueriedAttributes` to ask for everything the IDP releases to you. The query is signed with the service provider's key, and the answer is verified as a login is. The result describes the user but does not authenticate them: never start a session from it.

Messages on the SOAP back channel (attribute queries, artifact resolution and SOAP single logout, at both the service provider and the IDP) are sent only to `https` endpoints: an `http` endpoint in the peer's metadata is refused with an error matching `saml.ErrInsecureSOAPEndpoint` (the IDP instead treats it as missing and logs the participant out through the browser if it can). Set `AllowInsecureSOAPEndpoints` on the `ServiceProvider` or `IdentityProvider` to allow plain `http`, for tests and development only.

### Limiting where the service provider connects

The service provider makes HTTP requests to URLs it is given: the metadata URL of `RemoteMetadata`, `MDQMetadata` and `samlsp.FetchMetadata`, and the SOAP endpoints named in the IDP metadata, for artifact resolution, attribute queries and back-channel logout. When the metadata or its URL comes from someone you do not fully trust, such as the administrator of a tenant who registers their own IDP, those requests go wherever they say, including to services on your own network and to your cloud provider's metadata endpoint (server-side request forgery).

So the HTTP clients the package uses when you give none connect only to public addresses. Each address is checked as it is connected to, after DNS resolution, with [`code.dny.dev/ssrf`](https://pkg.go.dev/code.dny.dev/ssrf): private, loopback, link-local and the other IANA special-purpose ranges are refused, as are the IPv6 prefixes that embed an IPv4 address, whatever the URL's host name says and wherever a redirect leads. The proxy of the environment (`HTTPS_PROXY`) is still used.

To reach an IDP on your own network, such as one on `localhost` during development, give your own client with `samlsp.WithHTTPClient` (or the `HTTPClient` field of `ServiceProvider` and `IdentityProvider`, or the argument of `samlsp.FetchMetadata`). A client you give is used as it is, so if it may be sent to URLs from others, guard its dialer the same way:

```golang
guard := ssrf.New() // public unicast addresses, on ports 80 and 443
client := &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		DialContext: (&net.Dialer{Control: guard.Safe}).DialContext,
	},
}

idp := samlsp.RemoteMetadata(tenantMetadataURL, samlsp.WithHTTPClient(client))
config, err := samlsp.New(entityID, idp, samlsp.WithSigningKey(key, cert),
	samlsp.WithHTTPClient(client)) // artifact resolution, attribute queries, SOAP logout
```

An identity provider's back-channel requests, to the SOAP endpoints in service providers' metadata, are guarded the same way unless you give `idpslo.WithHTTPClient` or `IdentityProvider.HTTPClient`.

### Hardening

The `saml.ServiceProvider` that `x/samlsp` builds turns on checks that the core package leaves off for compatibility. It validates the authentication context, and refuses unknown conditions, AES-CBC encrypted assertions in unsigned Responses, SHA-1 signatures, expired IDP metadata, non-standard artifacts, and requests whose RelayState is longer than the 80 bytes the bindings allow.

Each accepted assertion and resolved artifact (and, with `x/samlsp/slo`, each logout request and logout response) is recorded until it expires, and refused if it comes again. By default the record is kept in memory, in a `replay.Memory` (`github.com/crewjam/saml/x/samlsp/replay`), which protects a single process; pass `samlsp.WithReplayState` a record that all processes share when there are several.

Some IDPs need a check relaxed. Microsoft Entra ID with token encryption, and Okta with an encrypted assertion, sign the assertion but not the Response, and encrypt with AES-CBC; older IDPs sign with SHA-1. Relax only the check the IDP needs:

```golang
config, err := samlsp.New(entityID, idp, samlsp.WithSigningKey(key, cert),
	samlsp.WithServiceProvider(func(sp *saml.ServiceProvider) {
		sp.RequireSignedResponseForCBC = false // this IDP signs only assertions
	}))
```

### More

- `github.com/crewjam/saml/x/samlsp/artifact` sends requests to the IDP with the HTTP-Artifact binding.
- `example/multitenant` is a multi-tenant SP in the manner of Supabase Auth: each tenant registers its own IDP, one `Config` serves them all with `WithIdentityProvider`, and logins in progress, the replay record and sessions live in a database (a pretend one), with SP- and IDP-initiated login and single logout.
- The [package documentation](https://pkg.go.dev/github.com/crewjam/saml/x/samlsp) and its examples cover the rest: `AuthnRequest` options such as `ForceAuthn` and `WithAuthnContext`, requested attributes and contacts in the SP metadata, signed metadata, and how to build other messages and bindings on it.

## Getting Started as an Identity Provider

An identity provider built into an application should use `github.com/crewjam/saml/x/samlidp`, with `x/samlidp/idpslo` for single logout and `x/samlidp/idpartifact` for the HTTP-Artifact binding. Like `x/samlsp`, it handles only the protocol: it verifies AuthnRequests and makes signed Responses, and the application keeps its own users, sessions and login pages. `example/idp/` is a complete example: a login page and in-memory sessions, a portal for IdP-initiated login, single logout that visits each service provider the session was used for, and service providers trusted by entity ID, whose metadata it fetches. Run it with `go run ./example/idp`, then `go run ./example` for a service provider that logs in with it.

The older package `samlidp` is a stand-alone IdP server with its own users and store, which is useful for testing. It registers service providers from the metadata sent to `PUT /services/:id`, and does not check signatures on it by default. Set `samlidp.Options.SPMetadataCertificates` to the service providers' (or their federation's) metadata signing certificates to accept only metadata signed with one of them; only what the signature covers is stored. A service provider served by this package signs its metadata with `ServiceProvider.SignedMetadata`.

### Single logout

`IdentityProvider.ServeSLO` handles SP initiated single logout: serve it at `LogoutURL`, and set `LogoutBindings` to `[]string{saml.HTTPRedirectBinding, saml.HTTPPostBinding}` so that the metadata advertises both bindings it accepts. (`IdentityProvider.Handler` serves it at `LogoutURL` for you; `samlidp` serves it at `/slo`.)

When a service provider sends a `LogoutRequest`, `ServeSLO`:

1. checks that it is well formed, comes from a service provider known to the `ServiceProviderProvider`, is addressed to `LogoutURL`, and is still current, and **verifies its signature** against the signing certificates in the service provider's metadata. With HTTP-Redirect that is a query string signature (`SigAlg` and `Signature`); with HTTP-POST an enveloped XML signature. Unsigned or invalid requests are rejected with HTTP 400 and no `LogoutResponse`, as the SLO profile requires requests to be authenticated.

1. ends the IdP session, if the `SessionProvider` also implements the optional `SessionInvalidator` interface. `IdpLogoutRequest.MatchesSession` tells whether a `Session` is one the request names, by its NameID and, if present, `SessionIndex` (the `Session.Index` given to the service provider at login):

   ```golang
   func (p *MySessionProvider) InvalidateSession(w http.ResponseWriter, r *http.Request, req *saml.IdpLogoutRequest) error {
   	session := p.lookupSession(r)
   	if req.MatchesSession(session) {
   		return p.deleteSession(w, session) // may set headers, e.g. to expire a cookie
   	}
   	return nil
   }
   ```

   The request may name several `SessionIndex` values; `MatchesSession` matches a session with any of them. A request may identify the principal with an `EncryptedID` instead of a NameID: it is decrypted with `Key`, if it is an RSA key, then with each of `DecryptionKeys`, and `req.Request.NameID` is set to the NameID it holds. The metadata publishes `EncryptionCertificate` (or `Certificate`) as the key to encrypt to; keep the previous key in `DecryptionKeys` while rotating it. A principal identified by a `BaseID` is refused unless `AcceptLogoutRequestBaseID` is set, in which case `req.Request.BaseID` holds it and the `SessionInvalidator` must interpret it.

1. sends a `LogoutResponse`, signed with the IdP's key (SHA-256 unless `SignatureMethod` says otherwise), to the service provider's `SingleLogoutService`, preferring the binding the request came with, and passes back the `RelayState`. Its status is `Success`, or `Responder` if the session could not be ended or the `SessionProvider` is not a `SessionInvalidator`.

If the `SessionProvider` also implements `SessionParticipantTracker`, which records the service providers each session logged in to, `ServeSLO` sends a `LogoutRequest` to each of the session's other service providers before it answers, and `IdentityProvider.StartLogout` starts IdP-initiated logout of a session. Set `EncryptLogoutNameID` to send those requests an `EncryptedID` instead of a NameID, encrypted to each service provider's encryption certificate. A service provider whose metadata publishes none gets the NameID in the clear.

Without a `SessionParticipantTracker`, the IdP cannot contact the session's other service providers, yet answers a plain `Success`. SAML Core (§3.7.3.2) requires it to add the second-level status `PartialLogout` then; set `ReportPartialLogoutWithoutTracker` to do so. It is off by default, as a service provider might handle a second-level status poorly.

With `idpslo.BackChannel`, the IdP sends LogoutRequests to the SOAP endpoints in the service providers' metadata. Its default client connects only to public addresses; a client given with `idpslo.WithHTTPClient` is used as it is (see [Limiting where the service provider connects](#limiting-where-the-service-provider-connects)).

## Support

The SAML standard is huge and complex with many dark corners and strange, unused features. This package implements the most commonly used subset of these features required to provide a single sign on experience. The package supports at least the subset of SAML known as [interoperable SAML](https://kantarainitiative.github.io/SAMLprofiles/saml2int.html).

This package supports the **Web SSO** profile. Message flows from the service provider to the IDP are supported using the **HTTP Redirect** binding and the **HTTP POST** binding, and with `x/samlsp/artifact` the **HTTP Artifact** binding. Message flows from the IDP to the service provider are supported via the **HTTP POST** binding and, on the service provider side, the **HTTP Artifact** binding (`ParseResponse` resolves the artifact with the IDP's ArtifactResolutionService over SOAP). The identity provider in this package answers with HTTP POST, or HTTP POST SimpleSign (below); it does not issue artifacts.

The **Single Logout** profile is supported with the HTTP Redirect and HTTP POST bindings: SP initiated and IDP initiated logout on the service provider side (see [Logging out](#logging-out)), and SP initiated logout on the identity provider side (see [Single logout](#single-logout)).

Both directions also support the **HTTP POST SimpleSign** binding ([sstc-saml-binding-simplesign-cs-01](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-binding-simplesign-cs-01.pdf)), which posts the message like HTTP POST but signs it with a detached signature over the message XML, the RelayState and the signature algorithm, carried in the `SigAlg` and `Signature` form fields. The service provider accepts it at the ACS and for logout, and can send authentication requests and logout messages with it (`samlsp.WithBinding(saml.HTTPPostSimpleSignBinding)`; `samlsp.WithResponseBinding` asks for SimpleSign responses). The identity provider accepts SimpleSign authentication requests and answers with SimpleSign when the service provider's ACS endpoint uses that binding.

The package can produce signed SAML assertions, and can validate both signed and encrypted SAML assertions. As an identity provider it also encrypts the assertions it produces, both for SP-initiated and IdP-initiated (`ServeIDPInitiated`) logins, whenever the service provider's metadata publishes an encryption certificate (a `KeyDescriptor` with `use="encryption"`, or one with no `use`). The algorithms default to RSA-OAEP-MGF1P with SHA-1 and AES-128-CBC for compatibility; set `IdentityProvider.AssertionEncrypter` to choose others, for example `xmlenc.OAEP_SHA256()` with `AES256GCM`.

## RelayState

The _RelayState_ parameter allows you to pass user state information across the authentication flow. The most common use for this is to allow a user to request a deep link into your site, be redirected through the SAML login flow, and upon successful completion, be directed to the originally requested link, rather than the root.

Unfortunately, _RelayState_ is less useful than it could be. Firstly, it is **not** authenticated, so anything you supply must be signed to avoid XSS or CSRF. Secondly, the SAML bindings limit it to 80 bytes (saml-bindings-2.0-os sections 3.4.3 and 3.5.3), which precludes signing. Many IDPs accept longer values, so the core package does not enforce the limit unless `LimitRelayStateLength` is set on the `ServiceProvider` or `IdentityProvider`; `x/samlsp` sets it. A RelayState received in a request is always returned unchanged.

## Conformance notes

[SAMLConformance](http://docs.oasis-open.org/security/saml/v2.0/saml-conformance-2.0-os.pdf) and the bindings list algorithms an implementation MUST support. This package deliberately departs from that list where an algorithm is weak or rarely used:

| Algorithm | Required by | Status |
|---|---|---|
| DSA-SHA1 signatures (`SigAlg` of the HTTP-Redirect and HTTP-POST-SimpleSign bindings) | saml-bindings §3.4.4.1, SimpleSign §2.5 | Not supported: refused as an unsupported signature algorithm. Go's `crypto/x509` no longer verifies DSA. |
| HMAC-SHA1 XML signatures | saml-conformance §4.1 | Not supported: there is no shared-key configuration. |
| Triple DES (`tripledes-cbc`) block encryption | saml-conformance §4.2 | Implemented, but not accepted for decryption unless the application calls `xmlenc.RegisterDecrypter(xmlenc.TripleDES)`. |
| RSA-v1.5 (`rsa-1_5`) key transport | saml-conformance §4.2 | Implemented (`xmlenc.PKCS1v15()`), but not accepted for decryption unless the application calls `xmlenc.RegisterDecrypter(xmlenc.PKCS1v15())`: it is open to Bleichenbacher padding-oracle attacks. |

RSA-SHA1 signatures, AES-128/256 (CBC and GCM) and RSA-OAEP are supported; set `ServiceProvider.RejectSHA1Signatures` or `IdentityProvider.RejectSHA1Signatures` to refuse SHA-1 signatures.

## References

The SAML specification is a collection of PDFs (sadly):

- [SAMLCore](http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf) defines data types.

- [SAMLBindings](http://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf) defines the details of the HTTP requests in play.

- [SAMLProfiles](http://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf) describes data flows.

- [SAMLConformance](http://docs.oasis-open.org/security/saml/v2.0/saml-conformance-2.0-os.pdf) includes a support matrix for various parts of the protocol.

[SAMLTest](https://www.samltest.dev/) is a free SAML identity provider and SCIM directory for testing SAML service providers.

## Security Issues

Please do not report security issues in the issue tracker. Instead, report them privately through GitHub: on the [Security tab](https://github.com/crewjam/saml/security), choose **Report a vulnerability** (or go straight to [the advisory form](https://github.com/crewjam/saml/security/advisories/new)). See [SECURITY.md](SECURITY.md) for details. If your issue is *not* a security issue, please use the issue tracker so other contributors can help.
