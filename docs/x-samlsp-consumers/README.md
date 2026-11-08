# Porting real consumers to x/samlsp

These patches port four consumers of `github.com/crewjam/saml/samlsp` to the
experimental `x/samlsp` API on branch `claude/stoic-keller-ro3w9z`. They were
chosen from a GitHub code search for `"github.com/crewjam/saml/samlsp"` (524
hits) to cover the two common ways the library is used:

| Patch | Upstream commit | How it uses samlsp today |
|---|---|---|
| [`velociraptor.patch`](velociraptor.patch) | Velocidex/velociraptor `2e10297` | `samlsp.Middleware` with its cookie sessions, wrapped by its own authorization |
| [`saml-auth-proxy.patch`](saml-auth-proxy.patch) | itzg/saml-auth-proxy `6135cf7` | `samlsp.Middleware` heavily customized: own request tracker, JWE session codec, anonymous sessions |
| [`supabase-auth.patch`](supabase-auth.patch) | supabase/auth `35307ce` | multi-tenant: `samlsp.DefaultServiceProvider` per request, metadata in Postgres, key rotation |
| [`bloodhound.patch`](bloodhound.patch) | SpecterOps/BloodHound `2b7665d` | multi-tenant: hand-built `saml.ServiceProvider`, own replay table, mockable wrapper |

Apply with `git apply` at the root of each repository. Each one also needs its
`go.mod` to require a `github.com/crewjam/saml` version that contains `x/samlsp`;
the patches leave `go.mod` alone because there is no release yet. (They were
checked with `replace github.com/crewjam/saml => <this branch>`.)

## What each port changes

**Velociraptor.** The SAML authenticator now issues the same `VelociraptorAuth`
JWT cookie as the OIDC authenticators. It moves `getSignedJWTTokenCookie` off
`*Provider` so SAML can use it, and replaces `RequireAccount` with
`authenticateUserHandle`. It adds `/saml/login` and `/saml/acs` handlers, and
remembers the request ID with `x/samlsp/pending`, as OIDC does with its
`oauthstate` cookie. User
provisioning moves from every request to once per login. The entity ID and ACS
URL stay the same, so the IdP registration does not change.

**saml-auth-proxy.** Removes `request_tracker_cookie.go` and `anonymous.go` and
adds about 300 lines (`session.go`, `auth.go`) for the session cookie that the
middleware used to own: a signed JWT (with the JWE wrapper as before).
`x/samlsp/pending` replaces the request tracker, carrying the return URL as
its data. Behaviour is kept:
`StaticRelayState`, `InitiateSessionPath`, auth-verify, forwarded headers and
attribute header mappings all work as before.

**Supabase Auth.** One `samlsp.Config` serves every tenant. Its `MetadataFunc`
reads the SSO provider that the handler puts in the context.
`WithDecryptionKeys(next)` replaces the second `ParseResponse` that retried with
the rotation key. `WithMetadata` replaces the after-the-fact metadata editing.
The patch adds an assertion replay cache, which Supabase did not have, through a new
`saml_consumed_ids` table with a migration and cleanup.

**BloodHound.** `NewServiceProvider` becomes `NewSAMLConfig`, and the `Service`
wrapper and its mock now wrap `*samlsp.Config`. The binding switch, the POST
template and its hard-coded CSP hash are replaced by `Message.Write`. The
hand-written replay check is replaced by `WithReplayState` on the existing
`saml_consumed_identifiers` table, using a new `ConsumeSAMLAssertionID`. The
assertion count and expiry helpers go, because the library now does that work.
The login now remembers its request ID with `x/samlsp/pending`, which closes
the `BED-5071` TODO.

The three ports that use `x/samlsp/pending` need no new configuration. Each
derives the tracker's 32-byte key with HMAC-SHA256, under a fixed label, from a
secret the project already has: Velociraptor's frontend key, BloodHound's JWT
signing key, and saml-auth-proxy's SP private key (which signed its old
tracker cookie too).

## Findings

These came up in more than one port and are worth acting on in x/samlsp or its
documentation:

1. **Attribute keys changed.** `samlsp` sessions keyed attributes by
   FriendlyName, or by Name when there was none. `Attributes.Get` matches Name
   only. Any setting that names an attribute, such as Velociraptor's
   `saml_user_attribute: name` or saml-auth-proxy's `AttributeHeaderMappings`,
   silently stops matching. Both ports keep the old keys for compatibility. A
   migration note is needed.
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
   protects nothing. Both ports pass `WithReplayState`, but `New`'s
   documentation should say this.
5. **There is no `ParseMetadata`.** Supabase still imports the old
   `samlsp.ParseMetadata` for its models. BloodHound validates uploads with
   `samlsp.StaticMetadataBytes(b)(ctx)`.
6. **Hardening defaults hit multi-tenant SPs hardest.** Supabase and BloodHound
   accept arbitrary customer IdPs. With SHA-1 and unsigned-CBC refused, some
   tenants will break, so they need a per-provider switch passed through
   `WithServiceProvider`. The patches do not add one.

Two improvements came from porting:

- **Supabase used stale metadata after a refresh.** When stale IdP metadata was
  refreshed, the old code updated the XML but still verified against the
  descriptor it had parsed before the refresh. A rotated IdP certificate was
  therefore not trusted until the next login. The context-based `MetadataFunc`
  reads the refreshed XML.
- **Velociraptor's logoff did not end SAML sessions.** `/app/logoff.html`
  cleared only `VelociraptorAuth`, never samlsp's `token` cookie. With SAML
  issuing `VelociraptorAuth`, logoff works.

## Verification

None of the projects' tests were run. Running third-party test code was not
allowed in this environment.

| Patch | Checked |
|---|---|
| saml-auth-proxy | `go vet ./...` clean, tests included; the JWE codec tests were rewritten for the new types |
| supabase-auth | `go vet ./internal/api/ ./internal/models/` clean, tests included; `samlacs_test.go` was rewritten for `samlConfig` |
| velociraptor | `go vet ./api/authenticators/` clean, using throwaway stand-ins for its generated asset files |
| bloodhound | `go build` of the changed packages is clean. **Not updated:** the handler tests in `cmd/api/src/api/v2/auth/saml_test.go` (`ServeMetadata`, `SAMLLoginHandler`, `SAMLCallbackHandler`; 28 mock call sites) and `services/saml/saml_integration_test.go` still use the old `Service` signatures |
