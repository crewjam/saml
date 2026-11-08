# gosaml.dev

A SAML testing service built on this repository's library, in the spirit
of samltest.dev and samltool.io:

- **Test identity providers.** Users you define, any attributes, any
  NameID format. Register service providers by metadata (or let them in by
  fetching the metadata at their entity ID), then log in as any user, or
  answer with an error status to see how the SP copes. IdP-initiated
  login too. A login starts an IdP session, so later logins from the same
  browser are single sign-on (and IsPassive requests succeed).
- **Profiles.** A test IdP can imitate the shape of Okta's, Entra ID's or
  Shibboleth's default responses: entity ID, attribute names and name
  formats, NameID format, assertion IDs and session indexes, validity
  window, which of the Response and the assertion are signed (only the
  assertion for Entra ID, only the Response for Shibboleth), encryption
  algorithms, and (Shibboleth) the `shibmd:Scope` metadata extension. The
  shapes come from the products' real responses, including the Okta and
  Entra fixtures in `../../testdata`.
- **Test service providers.** Trust any IdP by its metadata, log in, and
  see what it asserted: NameID, attributes, authentication context, the
  decrypted assertion. When a Response is refused, see why: the full error
  chain from the library, and hints for common causes. Checks can be
  relaxed (SHA-1, unsigned AES-CBC) to find out which one an IdP fails.
- **Single logout** (`x/samlidp/idpslo`, `x/samlsp/slo`). Both sides keep
  sessions in the database. Logout started at an SP ends the IdP session
  and logs the user out of the session's other SPs, through the browser,
  or over SOAP with back-channel logout turned on; the IdP answers
  PartialLogout when one fails. IdP-initiated logout runs from the IdP's
  session page (`/idp/{id}/session`) or its management page. SPs can also
  log out locally only.
- **HTTP-Artifact** (`x/samlidp/idpartifact`, `x/samlsp/artifact`). An SP
  can ask for the Response by artifact; the IdP keeps it in the database
  and the SP resolves it at the IdP's ArtifactResolutionService, server to
  server. SPs can also send AuthnRequests by artifact, for IdPs that
  resolve them (the test IdPs do not).
- **Inspector.** Decodes a redirect URL, POST body, raw HTTP request,
  base64 (deflated or not) or XML: AuthnRequests, Responses, logout
  messages, artifacts and metadata. It is this module's `inspect` package
  compiled to WebAssembly, so it runs in the browser and what people paste
  is never sent to the server. Paste a certificate (PEM, base64 or the
  signer's metadata) to check XML signatures and HTTP-Redirect or
  HTTP-POST-SimpleSign query signatures against it; every XML signature
  is also checked with its own KeyInfo certificate, which shows whether
  the message was changed but not who signed it.

Every IdP and SP logs the messages it exchanges, decoded. Management pages
follow the log live with Server-Sent Events (`/manage/{secret}/live`): an
in-memory hub, since one process holds all the state, with catch-up from
`Last-Event-ID` when a browser reconnects.

## Everything is temporary

- Each IdP or SP is deleted `GOSAML_TTL` (24h) after it is created; a
  reaper runs every minute.
- The SQLite database is deleted at startup, and on Fly.io it lives on the
  machine's root filesystem with no volume, so every deploy or restart
  starts from nothing.
- Instances are named with memorable words from
  [`golang-petname`](https://github.com/dustinkirkland/golang-petname): a
  two-word public ID in protocol URLs (`/idp/comic-krill/metadata`) and a
  three-word management page (`/manage/wholly-blessed-mammoth`). They are
  easy to read and to guess; this is a testing service. The other IDs the
  service makes (logins and logouts in progress, sessions, default
  RelayStates, session indexes, transient NameIDs) are
  [Sqids](https://sqids.org/go) of random numbers, such as `86Rf07xd4z`.
- There are no accounts. Each instance has a public ID (in its protocol
  URLs) and a secret management URL, `/manage/{secret}`, which is its only
  credential. A cookie remembers the instances a browser created, so the
  home page can list them.

## Layout

| Path | What |
| --- | --- |
| `main.go` | Configuration (environment variables), startup, reaper |
| `server/` | The web app: `idp.go` uses `x/samlidp`, `sp.go` uses `x/samlsp` and `x/samlsp/pending` |
| `server/idp_flow.go`, `server/idp_slo.go` | IdP SSO, sessions, single logout, artifact resolution |
| `server/profiles.go` | The Okta-, Entra ID- and Shibboleth-like IdP profiles |
| `server/sp_slo.go` | SP sessions, single logout, artifact resolution |
| `server/backchannel.go` | The SOAP client (in-process for this server's own URLs) and the artifact store |
| `store/` | SQLite (`modernc.org/sqlite`, pure Go): instances, logs, pending logins and logouts, sessions, artifacts, and the library's replay state |
| `inspect/` | The message decoder, shared by the WebAssembly inspector and the server's logs |
| `wasm/` | The `js/wasm` entry point, which exposes `samlInspect(input, keys)` to the page |
| `web/` | `html/template` pages and static files, embedded in the binary |

It is a separate Go module so that its dependencies (SQLite) never reach
users of the library. `go.mod` replaces `github.com/crewjam/saml` with
`../..`, so the service always runs the library in this checkout.

## Running and deploying

```sh
./deploy.sh run      # build for this machine and serve http://localhost:8080
./deploy.sh build    # just build, into build/gosaml
./deploy.sh          # vet, test, cross-compile for linux/amd64, fly deploy
```

`deploy.sh` compiles the inspector to WebAssembly first, copying the
matching `wasm_exec.js` from the Go toolchain, so that both are embedded in
the server binary. The Docker image is only that binary on distroless.

First deploy:

```sh
fly apps create gosaml
fly certs add gosaml.dev    # then set DNS as `fly certs show gosaml.dev` says
./deploy.sh
```

Environment variables: `GOSAML_BASE_URL` (default
`http://localhost:8080`), `GOSAML_ADDR` (`:8080`), `GOSAML_DB` (a file in
the temporary directory), `GOSAML_TTL` (`24h`), `GOSAML_MAX_INSTANCES`
(`5000`).

## Security notes

- Every request the server makes on a visitor's behalf (metadata URLs,
  artifact resolution, SOAP logout) goes through a dialer guarded by
  [`code.dny.dev/ssrf`](https://pkg.go.dev/code.dny.dev/ssrf), which checks
  the address actually connected to, after DNS resolution, so redirects and
  DNS rebinding are covered too. It allows public unicast addresses only,
  refusing the IANA special-purpose ranges (private, loopback, link-local,
  CGNAT, Fly's private network, ...) and IPv6 transition prefixes that embed
  an IPv4 address (NAT64, 6to4, Teredo), and ports 80, 443, 8080 and 8443
  only. Requests also have no proxy, a 15s timeout and a 2 MiB cap. URLs of
  this server's own instances are served in-process; plain-http SOAP
  endpoints are allowed only when the server's own base URL is http (local
  development).
- Pages allow only the server's own scripts plus nonce'd inline scripts
  (for the self-submitting SAML forms) and `'wasm-unsafe-eval'`.
  `Referrer-Policy: same-origin` keeps management URLs from leaking to the
  SPs and IdPs a browser is sent to.
- The SP's result page shows the "Manage" link only to the browser that
  created the SP, since anyone can log in through a shared login link.
