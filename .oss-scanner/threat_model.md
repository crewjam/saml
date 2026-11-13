# Threat model: crewjam/saml

## What this project does and where untrusted input enters
crewjam/saml is a Go implementation of SAML 2.0 for both Service Providers (SP) and Identity Providers (IdP). Applications use it to make authentication decisions, so the core security goal is: **an attacker must not be able to cause the library to accept an identity, attribute, or session it should reject.**

Treat as attacker-controlled:
- Everything that arrives over a SAML binding: SAMLResponse / SAMLRequest / LogoutRequest / LogoutResponse via HTTP-POST, HTTP-Redirect (deflated + base64, with detached signature params), SimpleSign, SOAP, and the HTTP-Artifact binding (including ArtifactResponse bodies fetched from a peer).
- RelayState, query parameters, cookies, and form fields handled by `samlsp`, `x/samlsp`, `samlidp`, and `x/samlidp`.
- XML structure in general: element ordering, duplicate elements, namespaces/prefixes, comments, wrapping, size and depth.
- Metadata documents fetched or loaded at runtime (`samlsp.FetchMetadata`, aggregate metadata) are untrusted unless the caller verifies their signature; their size and structure are attacker-controlled either way.
- Encrypted assertions / NameIDs / EncryptedKey elements (attacker chooses algorithms, key-transport parameters, ciphertext).

Trusted: the application's configuration — its own keys and certificates, the pinned IdP/SP metadata it was configured with, entity IDs, ACS/SLO URLs, and the clock.

## Components that matter most / least
Most important (bugs here are typically high or critical):
- Response / Assertion validation in the root package (`service_provider.go`, `ParseResponse`, `ParseXMLResponse`, signature reference handling, `signature_reference.go`, `etree_xml.go`, `unmarshal_untrusted.go`): signature wrapping (XSW), comment/canonicalization tricks, unsigned or partially-signed assertions accepted, wrong signing key accepted, Audience / Destination / Recipient / InResponseTo / NotBefore / NotOnOrAfter / SubjectConfirmation checks bypassed, replay.
- XML encryption (`xmlenc/`): decryption oracles (CBC padding, error differentiation), algorithm confusion, key-wrap handling.
- Redirect / SimpleSign binding signature verification (`redirect_binding.go`, `simplesign_binding.go`).
- `x/samlsp` and `x/samlidp` (the recommended APIs) and their SLO / artifact subpackages.
- `samlsp` session handling: JWT session cookies, request tracking cookies, RelayState handling (open redirect, CSRF / login CSRF, session fixation), logout and revocation.
- IdP side (`identity_provider*.go`, `samlidp`): AuthnRequest validation, ACS URL selection, signing the right content, logout propagation.

Less important but in scope:
- Denial of service through resource exhaustion on unauthenticated input (memory/CPU blowup from large, deep, or highly compressed XML; unbounded deflate; unbounded metadata fetch).
- Metadata generation and marshalling round-trips.

Out of scope:
- `example/` programs and `tools/gosamldev` (the gosaml.dev demo and inspector site) except where they reveal a library bug.
- `samlidp` is documented as a rudimentary test IdP; report issues in it, but rate missing production hardening (e.g., no rate limiting, weak default password storage choices made explicit by the caller) as low.
- Vulnerabilities in third-party dependencies unless this library uses them in an unsafe way.

## How to exercise it
- `go test ./...` at the repository root runs the full suite; tests are self-contained and use fixtures in `testdata/` directories (signed responses, metadata, keys).
- `tools/gosamldev` is a separate Go module (with a replace directive pointing at the root) — `cd tools/gosamldev && go test ./...`.
- Good proof of a finding is a Go test in the relevant package that builds or mutates a fixture (e.g. a signed Response from `testdata/`) and shows `ParseResponse` / middleware accepting it when it should not.

## How you rate severity
- **Critical**: authentication bypass or impersonation an unauthenticated attacker can achieve against a default/recommended configuration — e.g. forging or altering an assertion that is accepted, signature wrapping, accepting an assertion signed by an untrusted key, decrypting/forging encrypted assertions.
- **High**: bypass of a security check that requires an unusual but supported configuration, or that needs a captured valid assertion (replay, audience/recipient/destination confusion, cross-SP assertion reuse), session forgery, open redirect leading to token theft, practical decryption oracles.
- **Medium**: login CSRF, open redirect without credential exposure, information leaks, unauthenticated DoS (memory/CPU amplification, panics on attacker input).
- **Low**: DoS that requires authenticated or trusted input (e.g. the configured metadata), hardening issues, spec deviations with no demonstrated security impact.
- A panic on attacker-controlled input is at least medium.

## How we'd like reports and patches
- Include a minimal Go test that reproduces the issue against the current `main`.
- Patches should be small, keep the existing public API, and include the reproducing test. Prefer rejecting malformed input over trying to repair it.

## Anything to leave alone
- SHA-1 signatures are allowed only when the caller opts in (`sha1_policy.go`); don't report SHA-1 acceptance under an explicit opt-in.
- Clock skew tolerance is configurable; don't report the default skew as a vulnerability.
- Known, documented spec deviations are listed in `conformance_deviations_test.go`; don't report those unless they have security impact not described there.
