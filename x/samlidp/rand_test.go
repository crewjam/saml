package samlidp_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/crewjam/saml/x/samlidp"
)

func TestWithRand(t *testing.T) {
	keys(t)
	sps := samlidp.StaticServiceProviders()
	key := samlidp.WithSigningKey(idpKey, idpCert)

	c, err := samlidp.New(idpEntityID, sps, key)
	if err != nil {
		t.Fatal(err)
	}
	if c.Rand() != rand.Reader {
		t.Errorf("without WithRand, Rand() is %v, not crypto/rand", c.Rand())
	}
	if c.IdentityProvider().Rand != rand.Reader {
		t.Errorf("without WithRand, the IdentityProvider's Rand is %v, not crypto/rand", c.IdentityProvider().Rand)
	}

	randReader := bytes.NewReader(nil)
	c, err = samlidp.New(idpEntityID, sps, key, samlidp.WithRand(randReader))
	if err != nil {
		t.Fatal(err)
	}
	if c.Rand() != randReader {
		t.Errorf("Rand() is %v, not the reader of WithRand", c.Rand())
	}
	if c.IdentityProvider().Rand != randReader {
		t.Errorf("the IdentityProvider's Rand is %v, not the reader of WithRand", c.IdentityProvider().Rand)
	}
}
