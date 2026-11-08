package replay_test

import (
	"log"

	"github.com/crewjam/saml/x/samlsp"
	"github.com/crewjam/saml/x/samlsp/replay"
)

// One record can serve several Configs of a process, for example one per
// tenant, so that a message accepted by one is refused by the others.
func ExampleNewMemory() {
	accepted := replay.NewMemory()
	for _, tenant := range []string{"acme", "globex"} {
		config, err := samlsp.New(samlsp.StaticMetadataBytes(idpMetadata(tenant)),
			"https://"+tenant+".example.com/saml/metadata",
			samlsp.WithReplayState(accepted))
		if err != nil {
			log.Fatal(err)
		}
		_ = config
	}
}

// idpMetadata returns the metadata of the tenant's IdP.
func idpMetadata(string) []byte { return nil }
