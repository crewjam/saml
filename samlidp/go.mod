module github.com/crewjam/saml/samlidp

replace github.com/crewjam/saml => ../

go 1.13

require (
	github.com/crewjam/saml v0.0.0-00010101000000-000000000000
	github.com/golang-jwt/jwt/v4 v4.2.0
	github.com/mattermost/xml-roundtrip-validator v0.1.0
	github.com/zenazn/goji v1.0.1
	golang.org/x/crypto v0.0.0-20211215153901-e495a2d5b3d3
	gotest.tools v2.2.0+incompatible
)
