package replay_test

import (
	"context"
	"database/sql"
	"log"

	"github.com/crewjam/saml/x/samlsp"
	"github.com/crewjam/saml/x/samlsp/replay"
)

// One record can serve several Configs of a process, for example one per
// tenant, so that a message accepted by one is refused by the others.
func ExampleNewMemory() {
	accepted := replay.NewMemory()
	for _, tenant := range []string{"acme", "globex"} {
		entityID := "https://" + tenant + ".example.com/saml/metadata"
		config, err := samlsp.New(entityID, samlsp.StaticMetadataBytes(idpMetadata(tenant)),
			samlsp.WithReplayState(accepted))
		if err != nil {
			log.Fatal(err)
		}
		_ = config
	}
}

// idpMetadata returns the metadata of the tenant's IdP.
func idpMetadata(string) []byte { return nil }

// The processes that serve an SP share a record in a database table, so
// that a message accepted by one is refused by the others.
func ExampleNewSQL() {
	db := openDatabase() // sql.Open with the driver of your database
	accepted, err := replay.NewSQL(db, replay.PostgreSQL, "")
	if err != nil {
		log.Fatal(err)
	}
	// Or run the statements of replay.Schema with your migrations.
	if err := accepted.CreateTable(context.Background()); err != nil {
		log.Fatal(err)
	}
	config, err := samlsp.New("https://sp.example.com/saml/metadata",
		samlsp.StaticMetadataBytes(idpMetadata("acme")), samlsp.WithReplayState(accepted))
	if err != nil {
		log.Fatal(err)
	}
	_ = config
}

// openDatabase returns the application's database.
func openDatabase() *sql.DB { return nil }
