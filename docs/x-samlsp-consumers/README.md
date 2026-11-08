# Porting real consumers to x/samlsp

These patches port consumers of `github.com/crewjam/saml/samlsp` to the
`x/samlsp` API, to find out what the API is like to use in real code. The
consumers were found with a GitHub code search for
`"github.com/crewjam/saml/samlsp"` and ranked by stars (the survey below).

| Patch | Upstream commit | How it uses samlsp today |
|---|---|---|
| [`zitadel.patch`](zitadel.patch) | zitadel/zitadel `62c9668` | multi-IdP broker: the middleware's request tracker and options as building blocks, login state in its own storage |
| [`velociraptor.patch`](velociraptor.patch) | Velocidex/velociraptor `2e10297` | `samlsp.Middleware` with its cookie sessions, wrapped by its own authorization |
| [`octelium.patch`](octelium.patch) | octelium/octelium `5f74171` | multi-IdP broker: hand-built `saml.ServiceProvider`, metadata helpers, login state server-side |
| [`bloodhound.patch`](bloodhound.patch) | SpecterOps/BloodHound `2b7665d` | multi-tenant: hand-built `saml.ServiceProvider`, own replay table, mockable wrapper |
| [`kubepi.patch`](kubepi.patch) | 1Panel-dev/KubePi `e183085` | `samlsp.Middleware` whose cookie session carries the login into KubePi's own session |
| [`supabase-auth.patch`](supabase-auth.patch) | supabase/auth `35307ce` | multi-tenant: `samlsp.DefaultServiceProvider` per request, metadata in Postgres, key rotation |
| [`saml-auth-proxy.patch`](saml-auth-proxy.patch) | itzg/saml-auth-proxy `6135cf7` | `samlsp.Middleware` heavily customized: own request tracker, JWE session codec, anonymous sessions |

Apply with `git apply` at the root of each repository. Each one also needs its
`go.mod` to require a `github.com/crewjam/saml` version that contains `x/samlsp`;
the patches leave `go.mod` alone because there is no release yet. (They were
checked with `replace github.com/crewjam/saml => <this repository>`.)

## Survey

On 2026-11-08, 305 public repositories imported `samlsp` (813 files). The 26
most popular, other than this one:

| # | Repository | Stars | How it uses samlsp | Port |
|---|---|---|---|---|
| 1 | gravitational/teleport | 21,078 | `ParseMetadata` on **SP** metadata, as an IdP; its SAML login builds `saml.ServiceProvider` itself | none: see finding 7 |
| 2 | zitadel/zitadel | 15,544 | middleware types (`TrackedRequest`, `RequestTracker`, `Options`) as building blocks of a multi-IdP broker | done |
| 3 | Velocidex/velociraptor | 4,428 | `Middleware` with its cookie sessions | done |
| 4 | octelium/octelium | 4,164 | `ParseMetadata`/`FetchMetadata`, own `saml.ServiceProvider`, multi-IdP | done |
| 5 | SpecterOps/BloodHound | 3,541 | `ParseMetadata`, own `saml.ServiceProvider`, multi-tenant | done |
| 6 | determined-ai/determined | 3,246 | `Middleware`, basic | skipped: no push since 2025-03 |
| 7 | 1Panel-dev/KubePi | 2,997 | `Middleware` with its sessions | done |
| 8 | supabase/auth | 2,595 | `DefaultServiceProvider`, `ParseMetadata`, multi-tenant | done |
| 9 | subspacecloud/subspace | 2,588 | `Middleware`, basic | skipped: no push since 2022 |
| 10 | cortezaproject/corteza | 2,187 | `Middleware` with its own request tracker and error handler | not yet |
| 11 | authorizerdev/authorizer | 2,118 | `ParseMetadata` on **SP** metadata, as an IdP | none: see finding 7 |
| 12 | siderolabs/omni | 1,428 | `Middleware` heavily customized: request tracker, assertion handler | not yet |
| 13 | paralus/paralus | 1,214 | `Middleware` with its own session provider and request tracker | not yet |
| 14 | buildbuddy-io/buildbuddy | 803 | `Middleware` with its own session and tracked-request codecs | not yet |
| 15 | apache/dubbo-go-pixiu | 566 | `Middleware` in a gateway filter, session attributes | not yet |
| 16 | terralist/terralist | 525 | `FetchMetadata`, own `saml.ServiceProvider` | not yet |
| 17 | cordum-io/cordum | 510 | `ParseMetadata`/`FetchMetadata`, `DefaultServiceProvider` | not yet |
| 18 | smhanov/auth | 447 | `Middleware`, basic | not yet |
| 19 | Windshiftapp/core | 414 | `FetchMetadata`, own `saml.ServiceProvider` | not yet |
| 20 | ZerkerEOD/krakenhashes | 408 | the `Session` and `Attributes` types only | not yet |
| 21 | novalagung/dasarpemrogramangolang-example | 363 | `Middleware` in a tutorial | not yet |
| 22 | MatthewJohn/terrareg | 348 | `ParseMetadata`, own `saml.ServiceProvider` | not yet |
| 23 | CorrectRoadH/OpenTickly | 319 | `ParseMetadata` | not yet |
| 24 | TUM-Dev/gocast | 263 | `Middleware`, basic | not yet |
| 25 | in4it/ecs-deploy | 259 | `Middleware`, basic | not yet |
| 26 | presbrey/beyond | 255 | `Middleware` with session attributes | not yet |

itzg/saml-auth-proxy, also ported, is 38th, with 76 stars.

Most consumers use `samlsp` in one of three ways:

- **The middleware** (15 of the 26): `Middleware` and its sessions, often with
  a customized request tracker, session codec or error handler. The port
  replaces the middleware's session with the application's own, and its
  request tracker with `x/samlsp/pending` or the application's own login state.
- **Metadata helpers beside their own `saml.ServiceProvider`** (8): these
  build the service provider themselves, usually because they serve many
  IdPs. The port replaces the hand-built service provider with a `Config` and
  the helpers with `ParseMetadata`, `StaticMetadata` and `RemoteMetadata`.
- **As an IdP** (2, including the most popular): `ParseMetadata` to read the
  metadata of the SPs they serve. `x/samlsp` has nothing for them.

## What each port changes

**Velociraptor.** The SAML authenticator now issues the same `VelociraptorAuth`
JWT cookie as the OIDC authenticators. It moves `getSignedJWTTokenCookie` off
`*Provider` so SAML can use it, and replaces `RequireAccount` with
`authenticateUserHandle`. It adds `/saml/login` and `/saml/acs` handlers, and
remembers the request ID with `x/samlsp/pending`, as OIDC does with its
`oauthstate` cookie. A `saml_user_attribute` that names a FriendlyName keeps
matching through `Attributes.LegacyMap`. User provisioning moves from every request to once per login. The entity ID and ACS
URL stay the same, so the IdP registration does not change.

**saml-auth-proxy.** Removes `request_tracker_cookie.go` and `anonymous.go` and
adds about 300 lines (`session.go`, `auth.go`) for the session cookie that the
middleware used to own: a signed JWT (with the JWE wrapper as before).
`x/samlsp/pending` replaces the request tracker, carrying the return URL as
its data. Behaviour is kept:
`StaticRelayState`, `InitiateSessionPath`, auth-verify, forwarded headers and
attribute header mappings all work as before.

**Supabase Auth.** One `samlsp.Config`, made with no `MetadataFunc`, serves
every tenant: each call names the SSO provider's IdP with
`WithIdentityProvider`.
`WithDecryptionKeys(next)` replaces the second `ParseResponse` that retried with
the rotation key. `WithMetadata` replaces the after-the-fact metadata editing.
The patch adds an assertion replay cache, which Supabase did not have, through a new
`saml_consumed_ids` table with a migration and cleanup. Each record is the
32-byte `samlsp.ReplayKey` (a hash of the IdP's entity ID and the message ID),
written with the request's context, so one table safely serves every tenant. Uploaded and stored metadata is checked with
`samlsp.ParseMetadata`, so the old `samlsp` package is no longer imported. For
an IdP-initiated Response, `samlsp.PeekUnverifiedIssuer` replaces the hand-written decode
of the unverified Issuer. Its separate `Destination` check is dropped: each
dedicated scope has its own `Config`, whose ACS URL `ParseResponse` checks the
`Destination` and the assertion's `Recipient` against, as Supabase's comment
noted.

**BloodHound.** `NewServiceProvider` becomes `NewSAMLConfig`, and the `Service`
wrapper and its mock now wrap `*samlsp.Config`. The binding switch, the POST
template and its hard-coded CSP hash are replaced by `Message.Write`. The
hand-written replay check is replaced by `WithReplayState` on the existing
`saml_consumed_identifiers` table, using a new `ConsumeSAMLAssertionID` with the
request's context; it stores the hex-encoded replay key as the identifier. Uploaded metadata is checked with `samlsp.ParseMetadata`. The
assertion count and expiry helpers go, because the library now does that work.
The login now remembers its request ID with `x/samlsp/pending`, which closes
the `BED-5071` TODO. As before, AuthnRequests are signed, metadata that
describes no IdP fails when the config is built, and a database failure while
recording an assertion is reported as a technical failure
(`ErrSAMLAssertionNotRecorded`), not as an invalid response.

Its tests are updated: the login handler tests run the real `Client`, so they
check the signed redirect, the POST form and the pending-login cookie; the
callback tests mock `ParseResponse` with the errors the library returns for a
replay or a failed record; a new test runs a login and its callback, checking
that only the browser that started the login has its request ID required; the
metadata test parses the served metadata; and `ConsumeSAMLAssertionID` and the
replay record's error mapping have tests of their own.

**Zitadel.** A multi-IdP broker that already keeps its login state (the
AuthnRequest ID) in its own storage, so it adds no cookie. Each provider's
`Config` is built per request, with one shared replay record; entity ID, ACS
and SLO URLs, signing and decryption are unchanged. Its request tracker
becomes a small type of its own. Federated logout uses `x/samlsp/slo` instead
of a hand-written form, so logout requests are now always signed. Three
hardening checks are turned back off for compatibility, each with its reason:
expired IdP metadata (Zitadel stores metadata once and never refreshes it),
SHA-1 signatures, and AES-CBC in unsigned Responses (Entra ID). The library
version Zitadel uses today does not make these checks, so this keeps today's
behaviour. Its test SP and test helpers are ported too.

**Octelium.** A multi-IdP broker that built its own `saml.ServiceProvider`.
Each connector gets a `Config`, rebuilt when the provider list changes, with a
replay record shared across rebuilds. Remote metadata is now refreshed instead
of fetched once. Its server-side login state is kept, and the request ID is now
required on every callback (a missing one used to panic).

**KubePi.** Used the middleware's cookie session only to carry the login into
its own session. The ACS now verifies the Response, requiring this browser's
request ID through `x/samlsp/pending`, and starts KubePi's session directly, so
there is no SAML session any more and each SSO login goes to the IdP. A
`Config` is built per login (its URLs come from the request), with a shared
replay record. `givenName` and `email` still match by FriendlyName, where IdPs
send them so.

The four ports that use `x/samlsp/pending` need no new configuration. Each
derives the tracker's 32-byte key with HMAC-SHA256, under a fixed label, from a
secret the project already has: Velociraptor's frontend key, BloodHound's JWT
signing key, and the SP private key for saml-auth-proxy (which signed its old
tracker cookie too) and KubePi. The others keep login state server-side.

The ports that had an SP key keep accepting encrypted assertions:
`WithSigningKey` only signs, so each also passes its RSA key to
`WithEncryptionKey`, as the old middleware used one key for both. (Supabase does so only when encrypted assertions are allowed,
which replaces its filtering of the metadata's key descriptors.)

## Findings

These came up in more than one port and are worth acting on in x/samlsp or its
documentation:

1. **Attribute keys changed.** `samlsp` sessions keyed attributes by
   FriendlyName, or by Name when there was none. `Attributes.Get` matches Name
   only. Any setting that names an attribute, such as Velociraptor's
   `saml_user_attribute: name` or saml-auth-proxy's `AttributeHeaderMappings`,
   silently stops matching. **Addressed:** `Attributes.LegacyMap` keys them as
   `samlsp` did. It is deprecated from the start, as a migration aid: both
   ports use it to keep existing configuration working, and should move
   their settings to attribute Names, which `Get` matches.
2. **A solicited Response now needs its request ID.** BloodHound called
   `ParseResponse(..., nil)` with `AllowIDPInitiated`. That accepted any
   Response, including one answering an AuthnRequest that some other browser
   started. With `x/samlsp` that Response fails unless `WithRequestID` matches.
   So every port had to add a pending-request cookie.
3. **Every port wrote the same pending-request cookie.** Each one is keyed by
   RelayState, scoped to the ACS path, and needs `SameSite=None; Secure`, or
   browsers drop it on the IdP's cross-site POST. That boilerplate is easy to get
   wrong. **Addressed:** `x/samlsp/pending` now provides it, and the
   Velociraptor, saml-auth-proxy and BloodHound patches use it. Supabase keeps
   pending logins server-side in its relay-state table and needs no cookie.
4. **A Config per request drops replay protection.** Multi-tenant apps whose
   entity ID or ACS URL differs per tenant (BloodHound, and Supabase's dedicated
   scopes) build a `Config` per request. The default in-memory replay state then
   protects nothing. **Addressed:** `New` documents this, with a per-request
   example that shares the replay record and the pending tracker. Replay state
   now gets the call's context (`samlsp.ReplayState`), so neither port captures
   the request's context in a per-request adapter any more.
5. **There was no `ParseMetadata`.** **Addressed:** `samlsp.ParseMetadata`
   checks metadata as `StaticMetadataBytes` does; Supabase and BloodHound use it
   to validate uploads.
6. **Hardening defaults hit multi-tenant SPs hardest.** Supabase, BloodHound,
   Octelium and Zitadel accept arbitrary customer IdPs. With SHA-1 and
   unsigned-CBC refused, some will break, so they need a per-provider switch
   passed through `WithServiceProvider`. Zitadel adds a further case: an app
   that stores a metadata snapshot (the usual multi-tenant pattern, with
   `StaticMetadata`) stops working when the snapshot's `validUntil` passes,
   because `RejectExpiredIDPMetadata` is on. Zitadel turns the three checks
   off; the other patches leave them on.

The second round of ports, Zitadel, Octelium and KubePi, found these:

7. **Two IdPs among the most popular consumers have nothing in `x/samlsp`.**
   Teleport (1st) and Authorizer (11th) use `samlsp` only for `ParseMetadata`,
   on the metadata of the SPs they serve. `x/samlsp.ParseMetadata` accepts IdP
   metadata only, so they must keep the old package, or the library needs a
   role-neutral parser outside it. Zitadel keeps its own parser too:
   `ParseMetadata` has no `CharsetReader` for metadata that declares a
   non-UTF-8 encoding, and refuses an aggregate with several IdPs instead of
   taking the first.
8. **Every `pending` port derives its cookie key by hand**, four times with the
   same HMAC construction. A helper, such as `pending.KeyFrom(secret, label)`,
   would remove the step most easily got wrong.
9. **The Name-then-FriendlyName lookup is written twice** (Velociraptor,
   KubePi), each time building a whole `LegacyMap` for one value. A deprecated
   `Attributes.LegacyGet(name)` would make it one line.
10. **`RemoteMetadata` cannot fail fast.** It fetches when first needed, but
    Octelium and KubePi report a bad metadata URL when the IdP is configured,
    so both call the returned function themselves. That works, but nothing
    documents it.
11. **Configs are rebuilt for more reasons than per request.** Octelium rebuilds
    them when its configuration changes, KubePi per login, and Zitadel per
    request; all three need a shared replay record. `New` documents only the
    per-request case. KubePi's per-login Config also throws away the metadata
    cache of its `RemoteMetadata`, so every login fetches the metadata again.
12. **`Message` hides a POST form's fields.** Zitadel hands the AuthnRequest to
    API clients as a URL and form fields, and writes no HTML itself, so it
    reimplements the POST binding as a custom `Binding` just to capture the
    fields. A `Message.Form()` returning the action and fields would replace
    that. Octelium, which hands back a login URL, cannot use an IdP that offers
    only HTTP-POST at all.
13. **Smaller gaps**:
    - `WithSignatureMethod` refuses SHA-1 even for signing, though Zitadel's
      admin API offers RSA-SHA1 for AuthnRequests (it works around it with
      `WithServiceProvider`).
    - `ForceAuthn` cannot be set from a configuration boolean without a
      conditional append (Octelium).
    - `slo` needs the full `saml.NameID` where Zitadel stored only its value.
    - `WithResponseBinding` refuses HTTP-Redirect, which Zitadel's tests use.
    - Logging why a Response was refused needs `errors.As` to reach
      `saml.InvalidResponseError.PrivateErr` (Octelium, BloodHound, KubePi).

Improvements that came from porting:

- **Supabase used stale metadata after a refresh.** When stale IdP metadata was
  refreshed, the old code updated the XML but still verified against the
  descriptor it had parsed before the refresh. A rotated IdP certificate was
  therefore not trusted until the next login. The per-call IdP reads the
  refreshed XML when the call needs it.
- **Velociraptor's logoff did not end SAML sessions.** `/app/logoff.html`
  cleared only `VelociraptorAuth`, never samlsp's `token` cookie. With SAML
  issuing `VelociraptorAuth`, logoff works.
- **Replay protection where there was none.** Octelium, KubePi and Zitadel kept
  no record of accepted assertions; now each does (in memory, per process).
- **Smaller fixes.** KubePi wrote an error body after a successful login's
  redirect; Octelium panicked on a missing login state; Zitadel's
  HTTP-Redirect logout requests carried no proper signature.

## Verification

None of the projects' tests were run. Running third-party test code was not
allowed in this environment.

| Patch | Checked |
|---|---|
| saml-auth-proxy | `go vet ./...` clean, tests included; the JWE codec tests were rewritten for the new types |
| supabase-auth | `go vet ./internal/api/ ./internal/models/` clean, tests included; `samlacs_test.go` was rewritten for `samlConfig` |
| velociraptor | `go vet ./api/authenticators/` clean, using throwaway stand-ins for its generated asset files |
| bloodhound | `go vet` clean for the changed packages, tests included, with and without the `integration` build tag |
| octelium | `go vet ./authserver/providers/saml/` (tests included) and `go build ./...` clean in `cluster/authserver` |
| kubepi | `go vet` of the changed packages (tests included), `go build ./...` and `go vet ./internal/... ./cmd/...` clean, using throwaway stand-ins for its embedded web assets |
| zitadel | `go vet` clean for `internal/idp/providers/saml/...` (tests included) and the acceptance test SP. The other changed packages import Zitadel's generated protobuf code, which is not in its repository, so they were type-checked with a tool that tolerates missing imports: the only errors are those missing packages. This is weaker than `go vet` |
