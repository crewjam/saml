package samlsp

import (
	"testing"

	"gotest.tools/v3/assert"
)

// Options.RejectUnknownConditions turns on the ServiceProvider's refusal of
// assertions with conditions it does not understand; it is off by default.
func TestOptionsRejectUnknownConditions(t *testing.T) {
	opts := Options{URL: mustParseURL("https://sp.example.com/")}
	assert.Check(t, !DefaultServiceProvider(opts).RejectUnknownConditions)
	opts.RejectUnknownConditions = true
	assert.Check(t, DefaultServiceProvider(opts).RejectUnknownConditions)
}
