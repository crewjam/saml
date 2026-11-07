package samlsp

import (
	"testing"

	"gotest.tools/v3/assert"
)

// Options.RequireStandardArtifacts sets the ServiceProvider's option; it is
// off by default.
func TestOptionsRequireStandardArtifacts(t *testing.T) {
	opts := Options{URL: mustParseURL("https://sp.example.com/")}
	assert.Check(t, !DefaultServiceProvider(opts).RequireStandardArtifacts)
	opts.RequireStandardArtifacts = true
	assert.Check(t, DefaultServiceProvider(opts).RequireStandardArtifacts)
}
