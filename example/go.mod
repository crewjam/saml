module github.com/crewjam/saml/example

replace github.com/crewjam/saml => ../

replace github.com/crewjam/saml/samlidp => ../samlidp

go 1.13

require (
	github.com/crewjam/saml v0.0.0-00010101000000-000000000000
	github.com/dchest/uniuri v0.0.0-20200228104902-7aecb25e1fe5
	github.com/kr/pretty v0.3.0
	github.com/zenazn/goji v1.0.1
	golang.org/x/crypto v0.0.0-20211215153901-e495a2d5b3d3
)

require github.com/crewjam/saml/samlidp v0.0.0-00010101000000-000000000000
