# SAML

[![](https://godoc.org/github.com/crewjam/saml?status.svg)](http://godoc.org/github.com/crewjam/saml)

![Build Status](https://github.com/crewjam/saml/actions/workflows/test.yml/badge.svg)

Package saml contains a partial implementation of the SAML standard in golang.
SAML is a standard for identity federation, i.e. either allowing a third party to authenticate your users or allowing third parties to rely on us to authenticate their users.

## Introduction

In SAML parlance an **Identity Provider** (IDP) is a service that knows how to authenticate users. A **Service Provider** (SP) is a service that delegates authentication to an IDP. If you are building a service where users log in with someone else's credentials, then you are a **Service Provider**. This package supports implementing both service providers and identity providers.

The core package contains the implementation of SAML. The package samlsp provides helper middleware suitable for use in Service Provider applications. The experimental package x/samlsp provides a smaller, protocol-only service provider API that leaves sessions to the application (see [below](#a-protocol-only-service-provider-xsamlsp)). The package samlidp provides a rudimentary IDP service that is useful for testing or as a starting point for other integrations.

## Getting Started as a Service Provider

Let us assume we have a simple web application to protect. We'll modify this application so it uses SAML to authenticate users.

```golang
package main

import (
    "fmt"
    "net/http"
)

func hello(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "Hello, World!")
}

func main() {
    app := http.HandlerFunc(hello)
    http.Handle("/hello", app)
    http.ListenAndServe(":8000", nil)
}
```

Each service provider must have an self-signed X.509 key pair established. You can generate your own with something like this:

    openssl req -x509 -newkey rsa:2048 -keyout myservice.key -out myservice.cert -days 365 -nodes -subj "/CN=myservice.example.com"

We will use `samlsp.Middleware` to wrap the endpoint we want to protect. Middleware provides both an `http.Handler` to serve the SAML specific URLs **and** a set of wrappers to require the user to be logged in. We also provide the URL where the service provider can fetch the metadata from the IDP at startup. In our case, we'll use [samltest.dev](https://www.samltest.dev/), an identity provider designed for testing.

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
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/crewjam/saml/samlsp"
)

func hello(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, %s!", samlsp.AttributeFromContext(r.Context(), "displayName"))
}

func main() {
	keyPair, err := tls.LoadX509KeyPair("myservice.cert", "myservice.key")
	if err != nil {
		panic(err) // TODO handle error
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		panic(err) // TODO handle error
	}

	idpMetadataXML, err := os.ReadFile("idp-metadata.xml")
	if err != nil {
		panic(err) // TODO handle error
	}
	idpMetadata, err := samlsp.ParseMetadata(idpMetadataXML)
	if err != nil {
		panic(err) // TODO handle error
	}

	rootURL, err := url.Parse("http://localhost:8000")
	if err != nil {
		panic(err) // TODO handle error
	}

	samlSP, err := samlsp.New(samlsp.Options{
		URL:         *rootURL,
		Key:         keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate: keyPair.Leaf,
		IDPMetadata: idpMetadata,
	})
	if err != nil {
		panic(err) // TODO handle error
	}
	app := http.HandlerFunc(hello)
	http.Handle("/hello", samlSP.RequireAccount(app))
	http.Handle("/saml/", samlSP)
	panic(http.ListenAndServe(":8000", nil))
}
```

Next we'll have to register our service provider with the identity provider to establish trust from the service provider to the IDP. samltest.dev doesn't take an uploaded metadata file. Instead, set the app's SP ACS URL and SP Entity ID, either under "SAML SP Settings" on `https://www.samltest.dev/apps/<APP_ID>` or with the API:

    curl -X PUT https://www.samltest.dev/api/apps/<APP_ID> \
      -H "Content-Type: application/json" \
      -d '{"users":[{"email":"john@example.com","firstName":"John","lastName":"Doe"}],
           "spAcsUrl":"http://localhost:8000/saml/acs",
           "spEntityId":"http://localhost:8000/saml/metadata"}'

By default `samlsp` uses `<root URL>/saml/acs` as the ACS URL and `<root URL>/saml/metadata` as the entity ID (set `Options.AcsPath`, `Options.MetadataPath` and `Options.SloPath` to use different paths). You can view the service provider's metadata at `localhost:8000/saml/metadata`.

Now you should be able to authenticate. The flow should look like this:

1. You browse to `localhost:8000/hello`

1. The middleware redirects you to `https://www.samltest.dev/apps/<APP_ID>/login`

1. samltest.dev asks which of the app's test users you want to log in as. There is no password.

1. samltest.dev returns you an HTML document which contains an HTML form setup to POST to `localhost:8000/saml/acs`. The form is automatically submitted if you have javascript enabled.

1. The local service validates the response, issues a session cookie, and redirects you to the original URL, `localhost:8000/hello`.

1. This time when `localhost:8000/hello` is requested there is a valid session and so the main content is served.

### Reading the user's name, email and other attributes

You don't need to parse the SAML response yourself. After the middleware validates it, the handlers wrapped by `RequireAccount` can read the user's details from the request context:

```golang
func hello(w http.ResponseWriter, r *http.Request) {
	// The first value of an attribute, or "" if it is missing.
	email := samlsp.AttributeFromContext(r.Context(), "mail")

	session := samlsp.SessionFromContext(r.Context())

	// Every attribute, with all of its values.
	if s, ok := session.(samlsp.SessionWithAttributes); ok {
		for name, values := range s.GetAttributes() {
			fmt.Fprintf(w, "%s: %v\n", name, values)
		}
	}

	// The NameID from the assertion's Subject, often the user's email or ID.
	if claims, ok := session.(samlsp.JWTSessionClaims); ok {
		fmt.Fprintf(w, "NameID: %s, email: %s\n", claims.Subject, email)
	}
}
```

Each attribute is stored under its `FriendlyName`, or its `Name` when the IDP sends no `FriendlyName` (for example `urn:oid:0.9.2342.19200300.100.1.3` or `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress`). The IDP decides which attributes it sends and what they are called, so if one you expect is missing, check the IDP's attribute release settings. Listing every attribute as above shows exactly what you received. The `SessionIndex` attribute is added by this package, not sent as an attribute by the IDP.

Attributes the IDP encrypts (`EncryptedAttribute`) are decrypted with the service provider's key, like an encrypted assertion, and read like the others; an assertion with one that cannot be decrypted is refused. An assertion's Subject must identify the user with a NameID (possibly encrypted). One whose Subject has no identifier is refused, and so is one identified by a `BaseID`, unless `ServiceProvider.AcceptAssertionBaseID` is set: the assertion's `Subject.BaseID` then holds the element, which your code must interpret, and the session has no NameID.

### Logging out

The middleware serves the SAML Single Logout endpoint, `<root URL>/saml/slo`, alongside the metadata and ACS endpoints. To let users log out, route a path of your application to `HandleStartLogout`:

```golang
http.Handle("/saml/", samlSP)
http.HandleFunc("/logout", samlSP.HandleStartLogout)
```

When a user visits `/logout`:

1. `HandleStartLogout` deletes the session cookie and sends the browser to the IDP's `SingleLogoutService` with a `LogoutRequest` for the session's NameID and every `SessionIndex` of the assertion it was made from. It remembers the request's ID in a short-lived `samlslo_` cookie, scoped to the SLO URL, just as login remembers the `AuthnRequest`. It uses the HTTP-Redirect binding if the IDP supports it, and HTTP-POST otherwise. If the IDP has no `SingleLogoutService` in its metadata, only the local session is ended.

1. The IDP ends its own session and sends a `LogoutResponse` back to `/saml/slo`.

1. The middleware validates the response's signature, issuer, destination and status, checks that its `InResponseTo` is the ID of the request it sent from this browser, and redirects the user to `/`. A response the SP did not ask for, or one that is replayed, is rejected.

The middleware also handles IDP initiated logout: when the IDP sends a signed `LogoutRequest` to `/saml/slo`, the middleware deletes the session cookie of that browser and answers the IDP with a `LogoutResponse`. With the default session provider it also records the logout in its revocation store (see `Options.SessionRevocations`), so that copies of the session in other browsers are refused too: those with the request's `SessionIndex`, or every earlier session of the user if the request names none. If that fails (for example because the store is full), the error goes to `OnError` and the `LogoutResponse` carries `Success` with the second-level status `PartialLogout`: the browser's session has ended, but its copies may not have.

For single logout to work, the IDP needs to know the SLO URL. It is in the service provider's metadata, or you can enter `<root URL>/saml/slo` in the IDP's settings. The SAML single logout profile requires logout requests and responses sent with the HTTP-Redirect or HTTP-POST binding to be signed, and many IDPs enforce it. They are not signed by default: set `Options.SignLogout` to sign them with `Key` (`ServiceProvider.LogoutSignatureMethod`), or `Options.SignRequest`, which signs authentication requests too. If the IDP requires the NameID to be encrypted, set `ServiceProvider.EncryptLogoutNameID`: the request then carries an `EncryptedID`, encrypted to the encryption certificate in the IDP's metadata, with the strongest cipher the metadata lists for it, AES-256-GCM if it lists none. Set `ServiceProvider.LogoutNameIDEncrypter` for an IDP that cannot decrypt AES-GCM. If you need different behaviour, for example to end server-side sessions, the `ServiceProvider` methods `MakeLogoutRequest`, `RedirectLogoutRequestURL`, `ParseLogoutResponse`, `ValidateLogoutRequest` and `MakeRedirectLogoutResponse` are the building blocks `HandleStartLogout` and `ServeSLO` use.

SP initiated logout can also use the SOAP binding. With `Options.LogoutBinding` set to `saml.SOAPBinding`, and an IDP whose metadata lists a SOAP `SingleLogoutService`, `HandleStartLogout` sends the signed `LogoutRequest` to the IDP from the server rather than through the browser (back-channel logout), deletes the session cookie and redirects the user to `/`. If the IDP cannot be reached or does not answer `Success`, the error goes to `OnError`, the session cookie is deleted all the same, and the browser is sent to the IDP's front-channel `SingleLogoutService`, if it has one, with a `LogoutRequest` as described above.

### Trusting the IDP's metadata

The service provider trusts whatever signing certificates the IDP metadata names, so get the metadata from a source you trust:

- **A file kept with the service**, as above, checked when you download it and updated when the IDP rotates its keys.

- **Signed metadata.** If the IDP (or its federation) signs its metadata, fetch it and check the signature against the metadata signing certificate, obtained out of band:

  ```golang
  idpMetadata, err := samlsp.FetchSignedMetadata(context.Background(), http.DefaultClient,
  	*idpMetadataURL, []*x509.Certificate{idpMetadataSigningCert})
  ```

  Only what the signature covers is parsed. An IDP served by this package signs its metadata when `IdentityProvider.SignMetadata` is set.

- **An `https` URL you trust**, with `samlsp.FetchMetadata`. The metadata is then only as trustworthy as that server and its TLS certificate, and a plain `http` URL can be changed by anyone on the network path.

Federation metadata (an `<EntitiesDescriptor>` such as eduGAIN or InCommon publishes) holds many IDPs. `ParseMetadata` and `FetchMetadata` refuse metadata with more than one; use `ParseMetadataByEntityID`, `FetchMetadataByEntityID` or their `Signed` variants to choose the IDP by its entity ID.

### Querying attributes from the IDP

An IDP that is also a SAML attribute authority (for example Shibboleth) can be asked for a user's attributes outside of a login, with an `AttributeQuery` sent over the SOAP back channel (the Assertion Query/Request profile). This needs an `AttributeAuthorityDescriptor` with a SOAP `AttributeService` in the IDP metadata, and the IDP must be willing to answer this service provider:

```golang
// The NameID the IDP issued for the user, as received at login, so that its
// Format and qualifiers match what the IDP knows the user by.
nameID := saml.NameID{
	Format: string(saml.PersistentNameIDFormat),
	Value:  "AAdzZWNyZXQx...",
}
result, err := samlSP.ServiceProvider.QueryAttributes(ctx, nameID,
	saml.Attribute{Name: "urn:oid:0.9.2342.19200300.100.1.3", NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"})
if err != nil {
	return err
}
for _, attribute := range result.Attributes {
	for _, value := range attribute.Values {
		fmt.Println(attribute.Name, value.Value)
	}
}
```

Leave out the attributes to ask for everything the IDP releases to you. The query is signed with the service provider's key, and the response is accepted only if it answers this query, is signed by the IDP (the `Response`, or every `Assertion`), and every assertion is about the queried NameID, addressed to this service provider and currently valid. The result describes the user but does not authenticate them: never start a session from it. `QueryAttributes` sends the query with `ServiceProvider.HTTPClient`; to use your own transport, build the query with `MakeAttributeQuery`, send `query.SoapRequest()`, and validate the reply with `ParseXMLAttributeQueryResponse`.

Messages on the SOAP back channel (attribute queries, artifact resolution and SOAP single logout, at both the service provider and the IDP) are sent only to `https` endpoints: an `http` endpoint in the peer's metadata is refused with an error matching `saml.ErrInsecureSOAPEndpoint` (the IDP instead treats it as missing and logs the participant out through the browser if it can). Set `AllowInsecureSOAPEndpoints` on the `ServiceProvider` or `IdentityProvider` to allow plain `http`, for tests and development only.

With the `samlsp` middleware, `samlSP.QueryAttributes(r, attributes...)` queries the attributes of the user of the request's session. The default session records the NameID of the login, with its Format and qualifiers, for this purpose; a session issued by an earlier version does not, and the user must log in again (`QueryAttributes` then returns an error matching `samlsp.ErrSessionNameIDUnknown`).

## A protocol-only service provider: x/samlsp

The experimental package `github.com/crewjam/saml/x/samlsp` is a thin layer over `saml.ServiceProvider` shaped after `golang.org/x/oauth2` and `go-oidc`. It deals with the SAML protocol only: it builds requests, verifies responses and serves the SP metadata, and leaves sessions, cookies and the storage of pending requests to the application. Its API may change.

```golang
config, err := samlsp.New(
	samlsp.RemoteMetadata("https://idp.example.com/metadata"),
	"https://sp.example.com/saml/metadata", // the entity ID; the ACS is at .../saml/acs
	samlsp.WithKey(key, cert),
)

http.HandleFunc("/saml/metadata", config.ServeMetadata)

http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
	relayState := rand.Text()
	req, err := config.AuthnRequest(r.Context(), relayState)
	// ... handle err; remember req.ID under relayState, e.g. in a signed cookie
	req.Write(w)
})

http.HandleFunc("/saml/acs", func(w http.ResponseWriter, r *http.Request) {
	requestID := ... // the ID remembered under r.FormValue("RelayState")
	assertion, err := config.ParseResponse(r.Context(), r, samlsp.WithRequestID(requestID))
	// ... handle err; start the application's session from assertion.NameID
	// and assertion.Attributes (see Attributes.Decode)
})
```

It turns on every check that the core package leaves off only for compatibility, and refuses replayed assertions by default. It also covers attribute queries, MDQ metadata, requested attributes in the SP metadata, and decoding attributes into typed struct fields. See the [package documentation](https://pkg.go.dev/github.com/crewjam/saml/x/samlsp) and its examples.

Optional features are separate packages, built only on the public API of `x/samlsp`:

- `x/samlsp/slo` adds single logout, through the browser and, optionally, server to server with the SOAP binding:

  ```golang
  config, err := samlsp.New(idp, entityID, samlsp.WithKey(key, cert),
  	slo.Endpoint("https://sp.example.com/saml/slo"))
  logout, err := slo.New(config)
  msg, err := logout.Request(ctx, assertion.NameID, relayState, slo.WithSessionIndex(assertion.SessionIndexes...))
  ```

- `x/samlsp/artifact` sends requests to the IDP with the HTTP-Artifact binding.

## Getting Started as an Identity Provider

Please see `example/idp/` for a substantially complete example of how to use the library and helpers to be an identity provider.

`samlidp` registers service providers from the metadata sent to `PUT /services/:id`, and does not check signatures on it by default. Set `samlidp.Options.SPMetadataCertificates` to the service providers' (or their federation's) metadata signing certificates to accept only metadata signed with one of them; only what the signature covers is stored. A service provider served by this package signs its metadata with `ServiceProvider.SignedMetadata`.

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

## Support

The SAML standard is huge and complex with many dark corners and strange, unused features. This package implements the most commonly used subset of these features required to provide a single sign on experience. The package supports at least the subset of SAML known as [interoperable SAML](https://kantarainitiative.github.io/SAMLprofiles/saml2int.html).

This package supports the **Web SSO** profile. Message flows from the service provider to the IDP are supported using the **HTTP Redirect** binding and the **HTTP POST** binding. Message flows from the IDP to the service provider are supported via the **HTTP POST** binding and, on the service provider side, the **HTTP Artifact** binding (`samlsp.Options.UseArtifactResponse`; the artifact is resolved with the IDP's ArtifactResolutionService over SOAP). The identity provider in this package answers with HTTP POST, or HTTP POST SimpleSign (below); it does not issue artifacts.

The **Single Logout** profile is supported with the HTTP Redirect and HTTP POST bindings: SP initiated and IDP initiated logout on the service provider side (see [Logging out](#logging-out)), and SP initiated logout on the identity provider side (see [Single logout](#single-logout)).

Both directions also support the **HTTP POST SimpleSign** binding ([sstc-saml-binding-simplesign-cs-01](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-binding-simplesign-cs-01.pdf)), which posts the message like HTTP POST but signs it with a detached signature over the message XML, the RelayState and the signature algorithm, carried in the `SigAlg` and `Signature` form fields. The service provider accepts it at the ACS and for logout, and can send authentication requests and logout messages with it (`MakeSimpleSignAuthenticationRequest`, or `samlsp.Options.Binding`; `samlsp.Options.UseSimpleSignResponse` asks for SimpleSign responses). The identity provider accepts SimpleSign authentication requests and answers with SimpleSign when the service provider's ACS endpoint uses that binding.

The package can produce signed SAML assertions, and can validate both signed and encrypted SAML assertions. As an identity provider it also encrypts the assertions it produces, both for SP-initiated and IdP-initiated (`ServeIDPInitiated`) logins, whenever the service provider's metadata publishes an encryption certificate (a `KeyDescriptor` with `use="encryption"`, or one with no `use`). The algorithms default to RSA-OAEP-MGF1P with SHA-1 and AES-128-CBC for compatibility; set `IdentityProvider.AssertionEncrypter` to choose others, for example `xmlenc.OAEP_SHA256()` with `AES256GCM`.

### Hardening the service provider

Some protections the SAML profiles call for are opt-in, because turning them on by default could break working deployments. Consider enabling them:

- **Replay protection.** The Web Browser SSO profile says the service provider "MUST ensure that bearer assertions are not replayed". The tracking cookie already ties a response to the request this browser started, but an IDP-initiated response (`AllowIDPInitiated`) can be replayed until it expires unless a replay cache is configured. Set `Options.ReplayCache` (`ServiceProvider.ReplayCache`) to `samlsp.NewMemoryReplayCache(n)` for a single process, or to an `AssertionReplayCache` backed by a store shared by all instances. It also refuses replayed logout requests.

- **Signed logout messages.** Set `Options.SignLogout` (see [Logging out](#logging-out)).

- **Unknown conditions.** An assertion whose `<Conditions>` holds a condition this package does not understand (an extension `saml:Condition`, for example) is Indeterminate, and SAML Core says it MUST be rejected. Such conditions are ignored by default, since some IDPs send extension conditions. Set `Options.RejectUnknownConditions` (`ServiceProvider.RejectUnknownConditions`) to refuse them, or `ServiceProvider.ValidateUnknownConditions` to evaluate them yourself.

- **Artifact format.** With the HTTP-Artifact binding, a `SAMLart` that is not a standard type 0x0004 artifact, or whose SourceID is not the SHA-1 hash of the IDP's entityID, is sent to the IDP as is, since the ArtifactResponse it resolves to is fully checked anyway. Set `Options.RequireStandardArtifacts` (`ServiceProvider.RequireStandardArtifacts`) to refuse such an artifact without contacting the IDP. With a replay cache (above), each artifact is also resolved only once.

- **Integrity protection for CBC encryption.** An unsigned Response can carry an `EncryptedAssertion` whose signature is inside the encryption, so the service provider decrypts it before anything has authenticated it. With AES-CBC that is what padding and format oracle attacks on XML Encryption need, and the SAML Core errata (E93) say relying parties SHOULD require integrity protection before processing CBC-encrypted assertions. The SP metadata advertises AES-GCM first, but an IDP may still choose CBC. Set `Options.RequireSignedResponseForCBC` (`ServiceProvider.RequireSignedResponseForCBC`) to refuse, before decrypting, a CBC-encrypted assertion in a Response (or ArtifactResponse) that is not signed; the error matches `ErrInvalidSignature`. AES-GCM assertions are unaffected. Many IDPs sign only the assertion, so check that yours signs the Response, or encrypts with AES-GCM, before turning it on.

- **RelayState length.** The bindings limit RelayState to 80 bytes. Set `Options.LimitRelayStateLength` (`ServiceProvider.LimitRelayStateLength`, `IdentityProvider.LimitRelayStateLength`) to refuse to send a longer one. See [RelayState](#relaystate).

## Customizing the session lifetime

Sessions last one hour by default. This used to be set with `samlsp.Options.CookieMaxAge`, which has been removed. To change it, set the `MaxAge` of both the session cookie and the JWT it holds, then assign the provider to the middleware:

```golang
sessionMaxAge := 12 * time.Hour

codec := samlsp.DefaultSessionCodec(opts)
codec.MaxAge = sessionMaxAge

sessionProvider := samlsp.DefaultSessionProvider(opts)
sessionProvider.MaxAge = sessionMaxAge
sessionProvider.Codec = codec

samlSP, err := samlsp.New(opts)
if err != nil {
	return err
}
samlSP.Session = sessionProvider
```

Setting only the cookie's `MaxAge` is not enough: the browser keeps the cookie, but the token in it is rejected once the JWT expires.

## RelayState

The _RelayState_ parameter allows you to pass user state information across the authentication flow. The most common use for this is to allow a user to request a deep link into your site, be redirected through the SAML login flow, and upon successful completion, be directed to the originally requested link, rather than the root.

Unfortunately, _RelayState_ is less useful than it could be. Firstly, it is **not** authenticated, so anything you supply must be signed to avoid XSS or CSRF. Secondly, the SAML bindings limit it to 80 bytes (saml-bindings-2.0-os sections 3.4.3 and 3.5.3), which precludes signing. Many IDPs accept longer values, so this package does not enforce the limit unless `LimitRelayStateLength` is set on the `ServiceProvider` or `IdentityProvider` (`samlsp.Options.LimitRelayStateLength`); a RelayState received in a request is always returned unchanged.

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
