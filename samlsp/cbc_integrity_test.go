package samlsp

import (
	"testing"

	"gotest.tools/v3/assert"
)

// Options.RequireSignedResponseForCBC turns on the ServiceProvider's
// refusal to decrypt a CBC-encrypted assertion in an unsigned Response; it
// is off by default.
func TestOptionsRequireSignedResponseForCBC(t *testing.T) {
	opts := Options{URL: mustParseURL("https://sp.example.com/")}
	assert.Check(t, !DefaultServiceProvider(opts).RequireSignedResponseForCBC)
	opts.RequireSignedResponseForCBC = true
	assert.Check(t, DefaultServiceProvider(opts).RequireSignedResponseForCBC)
}
