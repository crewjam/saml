module github.com/adricasti/samlidp

go 1.23

toolchain go1.24.2

require github.com/crewjam/saml v0.5.1

require (
	github.com/beevik/etree v1.5.0 // indirect
	github.com/jonboulle/clockwork v0.2.2 // indirect
	github.com/mattermost/xml-roundtrip-validator v0.1.0 // indirect
	github.com/russellhaering/goxmldsig v1.4.0 // indirect
	golang.org/x/crypto v0.33.0 // indirect
)

// Replace the remote saml module with your local version
replace github.com/crewjam/saml => ../../
