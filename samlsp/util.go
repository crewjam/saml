package samlsp

import (
	"io"

	saml "github.com/kevcoxe/grafanaSaml"
)

func randomBytes(n int) []byte {
	rv := make([]byte, n)

	if _, err := io.ReadFull(saml.RandReader, rv); err != nil {
		panic(err)
	}
	return rv
}
