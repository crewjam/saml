package samlsp_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlsp"
)

func TestWithRand(t *testing.T) {
	cfg, err := samlsp.New(spEntityID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Rand() != rand.Reader {
		t.Errorf("without WithRand, Rand() is %v, not crypto/rand", cfg.Rand())
	}

	r := bytes.NewReader(nil)
	cfg, err = samlsp.New(spEntityID, nil, samlsp.WithRand(r))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Rand() != r {
		t.Errorf("Rand() is %v, not the reader of WithRand", cfg.Rand())
	}
	var got any
	cfg.Metadata(t.Context(), func(sp *saml.ServiceProvider) { got = sp.Rand })
	if got != r {
		t.Errorf("the ServiceProvider's Rand is %v, not the reader of WithRand", got)
	}
}
