# gosaml.dev

A SAML testing service built on this repository's library, in the spirit
of samltest.dev and samltool.io:

- **Test identity providers.** Users you define, any attributes, any
  NameID format. Register service providers by metadata (or let them in by
  fetching the metadata at their entity ID), then log in as any user, or
  answer with an error status to see how the SP copes. IdP-initiated
  login too.
- **Test service providers.** Trust any IdP by its metadata, log in, and
  see what it asserted: NameID, attributes, authentication context, the
  decrypted assertion. When a Response is refused, see why: the full error
  chain from the library, and hints for common causes. Checks can be
  relaxed (SHA-1, unsigned AES-CBC) to find out which one an IdP fails.
- **Inspector.** Decodes a redirect URL, POST body, raw HTTP request,
  base64 (deflated or not) or XML: AuthnRequests, Responses, logout
  messages, artifacts and metadata. It is this module's `inspect` package
  compiled to WebAssembly, so it runs in the browser and what people paste
  is never sent to the server.

Every IdP and SP logs the messages it exchanges, decoded.

## Everything is temporary

- Each IdP or SP is deleted `GOSAML_TTL` (24h) after it is created; a
  reaper runs every minute.
- The SQLite database is deleted at startup, and on Fly.io it lives on the
  machine's root filesystem with no volume, so every deploy or restart
  starts from nothing.
- There are no accounts. Each instance has a public ID (in its protocol
  URLs) and a secret management URL, `/manage/{secret}`, which is its only
  credential. A cookie remembers the instances a browser created, so the
  home page can list them.

## Layout

| Path | What |
| --- | --- |
| `main.go` | Configuration (environment variables), startup, reaper |
| `server/` | The web app: `idp.go` uses `x/samlidp`, `sp.go` uses `x/samlsp` and `x/samlsp/pending` |
| `store/` | SQLite (`modernc.org/sqlite`, pure Go): instances, logs, pending logins, and the library's replay state |
| `inspect/` | The message decoder, shared by the WebAssembly inspector and the server's logs |
| `wasm/` | The `js/wasm` entry point, which exposes `samlInspect(input)` to the page |
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

- Metadata URLs are fetched only from public addresses: the dialer refuses
  loopback, private, link-local and CGNAT addresses and Fly's private
  network, after DNS resolution. Ports are limited to 80, 443, 8080 and
  8443, size to 2 MiB, time to 15s. URLs of this server's own instances
  are answered locally, without a request.
- Pages allow only the server's own scripts plus nonce'd inline scripts
  (for the self-submitting SAML forms) and `'wasm-unsafe-eval'`.
  `Referrer-Policy: same-origin` keeps management URLs from leaking to the
  SPs and IdPs a browser is sent to.
- The SP's result page shows the "Manage" link only to the browser that
  created the SP, since anyone can log in through a shared login link.
