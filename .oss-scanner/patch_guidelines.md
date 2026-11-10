# How we would like patches made

## Size and scope of a fix
- Keep a fix narrow: change the code that is wrong, with no refactoring or renaming alongside it.
- If the same mistake is made at several call sites, fix them all in one patch, and say so.
- Keep the public API. If a fix must change behaviour that callers could rely on, make the safe behaviour the default, and only add an option to restore the old behaviour if a legitimate deployment needs it.
- Reject malformed or unexpected input with an error rather than trying to repair or guess at it.
- Do not add dependencies.

## Code style
- Format with gofmt and goimports, with github.com/crewjam/saml as the local import prefix. Code should pass golangci-lint with the .golangci.yml at the root.
- Comment only where the code is not obvious, for example to cite the spec section a check enforces.
- Error messages are lower case and say what was wrong with the input, without echoing secret material such as keys or decrypted content.

## Tests
- Add a regression test that fails before the fix and passes after it. Put it in a new _test.go file next to the code it covers, named for what it checks (for example sp_review_issuer_format_test.go), or in the existing test file for that function.
- Prefer table-driven tests built from fixtures in testdata/. Use the Clock and Rand fields rather than replacing package-level variables.
- go test ./... must pass in the root module and in tools/gosamldev.

## Branch and commit message
- Against main.
- Subject line: "package: what changed", lower case after the colon, imperative, no full stop. For example "sp: require the Response Issuer when signed".
- Body wrapped at 72 columns: what was wrong and what an attacker could do with it, then what the change does. Cite the spec section where one applies.
