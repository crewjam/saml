// Deprecated: the samlidp package is part of the github.com/crewjam/saml
// module. Import github.com/crewjam/saml/samlidp and require
// github.com/crewjam/saml instead of this module.
//
// This commit is not part of the main history. It exists only to be tagged
// samlidp/v0.0.1 so that the Go module proxy stops resolving the package
// github.com/crewjam/saml/samlidp to the stale nested module, whose pseudo-
// versions require the unresolvable github.com/crewjam/saml@v0.0.0-00010101000000-000000000000
// (https://github.com/crewjam/saml/issues/448).
module github.com/crewjam/saml/samlidp

go 1.17

require github.com/crewjam/saml v0.5.2

retract (
	// Pseudo-versions published while samlidp had its own go.mod. They
	// depend on github.com/crewjam/saml@v0.0.0-00010101000000-000000000000,
	// which cannot be downloaded.
	[v0.0.0-0, v0.0.0]
	// This version contains no packages; it exists only to publish the
	// retractions above.
	v0.0.1
)
