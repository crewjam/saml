module github.com/crewjam/saml/tools/gosaml

go 1.26.0

require (
	code.dny.dev/ssrf v0.3.0
	github.com/beevik/etree v1.8.1
	github.com/crewjam/saml v0.0.0
	github.com/dustinkirkland/golang-petname v0.0.0-20261016130456-fdd95a3d0543
	github.com/prometheus/client_golang v1.23.2
	github.com/russellhaering/goxmldsig v1.6.1
	github.com/sqids/sqids-go v0.4.1
	modernc.org/sqlite v1.62.0
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dustin/go-humanize v1.1.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/jonboulle/clockwork v0.5.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/ncruces/go-strftime v1.1.0 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.66.1 // indirect
	github.com/prometheus/procfs v0.16.1 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	go.yaml.in/yaml/v2 v2.4.2 // indirect
	golang.org/x/crypto v0.55.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	google.golang.org/protobuf v1.36.8 // indirect
	modernc.org/libc v1.80.1 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
)

// The tool is built from the library in this repository, so that it always
// exercises the current code. It is a separate module so that its
// dependencies (SQLite) never reach users of the library.
replace github.com/crewjam/saml => ../..
