module github.com/crewjam/saml

replace github.com/russellhaering/goxmldsig => github.com/cloudentity/goxmldsig v0.0.0-20220810145431-f5cb0a962e3a

go 1.18

require (
	github.com/beevik/etree v1.1.0
	github.com/crewjam/httperr v0.2.0
	github.com/golang-jwt/jwt/v4 v4.4.2
	github.com/google/go-cmp v0.5.8
	github.com/mattermost/xml-roundtrip-validator v0.1.0
	github.com/russellhaering/goxmldsig v1.2.0
	golang.org/x/crypto v0.0.0-20220722155217-630584e8d5aa
	gotest.tools v2.2.0+incompatible
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/jonboulle/clockwork v0.3.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
)
