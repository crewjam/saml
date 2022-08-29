module github.com/crewjam/saml

replace github.com/russellhaering/goxmldsig => github.com/cloudentity/goxmldsig v0.0.0-20220829102657-c391d786420d

go 1.18

require (
	github.com/beevik/etree v1.1.0
	github.com/crewjam/httperr v0.2.0
	github.com/golang-jwt/jwt/v4 v4.4.2
	github.com/google/go-cmp v0.5.8
	github.com/mattermost/xml-roundtrip-validator v0.1.0
	github.com/pkg/errors v0.9.1
	github.com/russellhaering/goxmldsig v1.2.0
	golang.org/x/crypto v0.0.0-20220826181053-bd7e27e6170d
	gotest.tools v2.2.0+incompatible
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/jonboulle/clockwork v0.3.0 // indirect
)
