# Handoff back: crewjam/saml open reports — what was done

Status as of 2026-11-07. All work is pushed and open as public PRs against `crewjam/saml` `main` (base `fcb1c8c`, #752). Ross approved PRs. PR text and commit messages avoid GHSA IDs and the word "security". Nothing is merged. No advisories, CVEs or releases were touched.

Environment notes: the local toolchain was Go 1.25.0 (`go.mod` says `go 1.25.0`), not 1.26. Every branch passes `go test ./...`. `golangci-lint run` reports only the `prealloc` finding at `service_provider.go:1535`, which is already on `main`.

## PRs, one line each

| Report | PR | Branch | What changed | Tests (fail on `main`) | Behaviour change |
|---|---|---|---|---|---|
| GHSA-2j2h-hc9p-g6gw (attrs from `xmlns:`) | [crewjam/saml#768](https://github.com/crewjam/saml/pull/768) | `fix/xmlns-attribute-confusion` | `unmarshalElement` sanitises a copy first: renames prefixes that could match an attribute field (anything not starting `[a-z]`) to `nsN`, drops namespaced attrs except `xml:`/`xsi:`. Also fixes #752's `IdpLogoutRequest.parseRequest` (same bug on the IdP side: verified on etree, unmarshalled raw bytes). | `TestAttributeNameIgnoresNamespaceDeclaration` and one per field, `TestParseXMLResponseIgnoresNamespaceDeclarationInSignedAssertion` (e2e, exc-c14n signed), `TestIDPLogoutRequestNotOnOrAfterIgnoresNamespaceDeclaration`, `TestUnmarshalledAttributeFieldsStartUpperCase` (invariant) | `x:Name` no longer read as `Name`; odd prefixes become `nsN` inside parsed etree values |
| GHSA-5cwg-vr83-6895 (xrv allocations) | [crewjam/saml#769](https://github.com/crewjam/saml/pull/769) | `fix/xml-roundtrip-allocations` | New `internal/xmlroundtrip` replaces `xml-roundtrip-validator` everywhere: one decoder plus a shared bufio writer. ~2,700 → ≤220 B/byte (2–3× etree's own parse). Differential fuzz: 200k docs, zero disagreements with xrv. Second commit: Redirect inflate cap 10 MB → 1 MiB, and fixes a `len(p)` bug in `saferFlateReader`. | `TestParseXMLResponseAllocationsBoundedByInputSize`, `TestValidateAllocationsBoundedByInputSize`, `TestSaferFlateReaderReadsMessageAtLimit` | Error text `xml: in token…`; dependency removed; Redirect > 1 MiB rejected |
| GHSA-88j8-qp3x-89g7 (unsigned-response DoS) | [crewjam/saml#770](https://github.com/crewjam/saml/pull/770) | `fix/unsigned-response-dos` | `findChildren` builds the namespace context once (2.6 s → 42 ms). An unsigned Response with more than one Assertion/EncryptedAssertion is refused (7.4 s → 0.13 s). Adds tests for two no-root checks that had none. #711 and the other no-root fixes already had tests. | `TestFindChildrenCostIndependentOfNamespaceDeclarations`, `TestUnsignedResponseWithManyAssertionsRejectedCheaply`, `TestUnsignedResponseMayCarryOnlyOneAssertion`, `TestLookupElementNamespaceMatchesSubContext`, `TestValidateLogoutRequestFormWithoutRootElement`, `TestSimpleSignMessageWithoutRootElement` | Unsigned Response with ≥2 assertions rejected; `TestMultipleAssertions` and XSW 3/5 tests updated |
| GHSA-pr5r-68p3-qv46 (CBC padding) | [crewjam/saml#771](https://github.com/crewjam/saml/pull/771) | `fix/cbc-padding` | Bad padding and malformed decrypted plaintext now return one `xmlenc.ErrDecryptionFailed`. **PKCS#7 all-bytes check deliberately not added** (see open question 1). | `TestDecryptionErrorsIndistinguishable`, `TestCBCDecryptBadPaddingReturnsErrDecryptionFailed`, `TestCBCDecryptAcceptsArbitraryPaddingBytes` | Detailed decrypt errors replaced by the generic one |
| GHSA-gg8v-q5p4-x8rp + GHSA-fvc9-q662-6qhg (metadata trust) | [crewjam/saml#772](https://github.com/crewjam/saml/pull/772) | `fix/metadata-trust` | `ParseMetadata` refuses an aggregate with more than one IdP. Opt-in `saml.VerifyMetadataSignature` and `samlsp.{Parse,Fetch}SignedMetadata[ByEntityID]` parse only the signed canonical bytes, which also blocks the 2j2h trick on metadata. README pins via a file; example IdP signs its metadata, example SP pins its cert. | `TestParseSignedMetadata` (10 subtests), `TestFetchSignedMetadata`, `TestParseMetadataRequiresSingleIDPInAggregate` | `ParseMetadata`/`FetchMetadata` fail on multi-IdP aggregates. No default made fail-closed. |
| Small: unbounded metadata read | [crewjam/saml#773](https://github.com/crewjam/saml/pull/773) | `fix/metadata-read-limit` | `samlsp.MaxMetadataSize` (256 MiB) caps the read | `TestFetchMetadataStopsReadingAtMaxMetadataSize` | > 256 MiB refused |
| Small: LogoutResponse InResponseTo | [crewjam/saml#774](https://github.com/crewjam/saml/pull/774) | `fix/logout-response-inresponseto` | Proposal: mark the 3 old validators `Deprecated:` in favour of `ParseLogoutResponse` (samlsp already uses it). No API change. | none (docs only) | none |
| GHSA-v94m-23rj-qv7v | — | — | Confirmed already covered: `TestIDPValidateRejectsMissingIssuer` (#712), `TestDecryptRejectsMalformedCiphertextLength` | — | — |

## Merge order and conflicts

The PRs are independent, all based on `main`, but they don't all merge cleanly together. A local branch `check/all-fixes-merged` (not pushed) has all seven merged, with tests and lint passing. Resolutions:

1. #768 vs #769, `identity_provider_logout.go`: keep `unmarshalElement(root, &req.Request)`, no `encoding/xml` import.
2. #769 vs #771, `decryptElement`: `if err := xmlroundtrip.Validate(plaintextEl); err != nil { return nil, xmlenc.ErrDecryptionFailed }`.
3. #772 after #769 (semantic, not textual): `metadata_verify.go` imports `xrv`. Change it to `xmlroundtrip.Validate(data)` and drop the `bytes` import, or the build breaks.
4. #772 vs #773, `samlsp/fetch_metadata.go`: keep both additions, then run `gofmt`.

Suggested order: #770, #768, #769, #771, #773, #772, #774.

## Open questions for Ross

1. **CBC / PKCS#7.** XML Enc §5.2 padding bytes are arbitrary. Santuario (Shibboleth) and .NET (ADFS/Entra) use ISO 10126 random bytes; this library pads with zeros. A PKCS#7 check would break those IdPs, so it was not added. CBC stays malleable regardless (Jager & Somorovsky 2011); AES-GCM is the real mitigation. Remaining distinguishable cases: "decrypted but signature invalid" vs "decrypt failed", and the joined multi-`DecryptionKeys` error. These show only in `PrivateErr`, which samlsp does not send to clients.
2. **Inflate cap 1 MiB** (#769, second commit) is beyond the report; drop that commit if unwanted.
3. **`MaxMetadataSize` = 256 MiB.** Current eduGAIN/InCommon aggregate sizes weren't verified.
4. Whether to drop the round-trip check entirely. On Go 1.25 the 2020 CVE constructs no longer reproduce; it was kept as cheap defence in depth.
5. Whether #774 should instead add the check, which would be an API break.

## Not done / possible follow-ups

- `validUntil` / `cacheDuration` not enforced on signed metadata, so an old signed copy can be replayed.
- Unbounded `io.ReadAll` of the artifact-resolution SOAP response (`service_provider.go:995`) and in `samlidp/util.go`.
- IdP `AuthnRequest` parsing still uses raw `xml.Unmarshal`. No enveloped signature is verified there, so the 2j2h trick gains nothing, but it could use `unmarshalElement` for consistency.
- Alternative or extra hardening for 2j2h: unmarshal the element goxmldsig returns from `Validate` (the canonical signed bytes) instead of the original. Not done because of the custom `SignatureVerifier` hook and the SimpleSign and signed-Response paths.

## Advisory bookkeeping (for Ross)

Advisories to update with fix PRs: 2j2h → #768, 5cwg → #769, 88j8 → #770, pr5r → #771 (partial; see question 1), gg8v/fvc9 → #772, 7287 follow-ups → #773/#774, v94m → already fixed by #712.
