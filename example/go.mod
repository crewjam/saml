module github.com/braineet/saml/example

replace github.com/braineet/saml => ../

replace github.com/braineet/saml/samlidp => ../samlidp

go 1.16

require (
	github.com/braineet/saml v0.0.0-00010101000000-000000000000
	github.com/dchest/uniuri v0.0.0-20200228104902-7aecb25e1fe5
	github.com/kr/pretty v0.3.0
	github.com/zenazn/goji v1.0.1
	golang.org/x/crypto v0.0.0-20220128200615-198e4374d7ed
)

require github.com/braineet/saml/samlidp v0.0.0-00010101000000-000000000000
