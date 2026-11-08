#!/bin/bash -eu
#
# Builds the fuzzers in this package for OSS-Fuzz. Called from the crewjam-saml
# project's build.sh in google/oss-fuzz, with the repository root as the
# working directory.

printf 'package fuzz\nimport _ "github.com/AdamKorcz/go-118-fuzz-build/testing"\n' > fuzz/register.go
go get github.com/AdamKorcz/go-118-fuzz-build/testing
go mod tidy

# Every func FuzzXxx(f *testing.F) in this package becomes a fuzzer of the same name.
for fuzzer in $(grep -ohE '^func Fuzz[A-Za-z0-9_]+\(f \*testing\.F\)' fuzz/*_test.go | sed -E 's/^func (Fuzz[A-Za-z0-9_]+).*/\1/'); do
  compile_native_go_fuzzer_v2 github.com/crewjam/saml/fuzz "$fuzzer" "$fuzzer"
done

# Seed corpora from the repository's fixtures.
seed() {
  local name=$1
  shift
  zip -qj "$OUT/${name}_seed_corpus.zip" "$@"
}
seed FuzzParseXMLResponse testdata/SP_SamlResponse testdata/*_response testdata/*_response.xml
seed FuzzParseXMLArtifactResponse testdata/TestParseXMLArtifactResponse_response
seed FuzzLogoutRequest testdata/TestSPCanProducePostLogoutRequest_form
seed FuzzLogoutResponseForm testdata/TestSPCanProducePostLogoutResponse_form
seed FuzzUnmarshal testdata/*Metadata* testdata/*_metadata* testdata/SP_AuthnRequest \
  testdata/SP_SamlResponse testdata/*decoded*
seed FuzzDecrypt $(find xmlenc/corpus xmlenc/crashers -type f ! -name '*.output' ! -name '*.quoted')
