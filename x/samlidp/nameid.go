package samlidp

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/crewjam/saml"
)

// transientNameIDBytes is the number of random bytes in a transient
// NameID: 160 bits, as saml-core §1.3.4 suggests for identifiers that
// must not collide, more than the 128 bits it requires.
const transientNameIDBytes = 20

// MinPairwiseKeySize is the smallest key, in bytes, that PairwiseNameID
// accepts: the output size of SHA-256.
const MinPairwiseKeySize = 32

// pairwiseDomain separates the HMACs of PairwiseNameID from any other use
// of the same key. Changing it changes every pairwise NameID.
const pairwiseDomain = "github.com/crewjam/saml/x/samlidp pairwise NameID v1\x00"

// TransientNameID returns a new transient NameID (saml-core §8.3.8): 160
// bits read from the Config's source of random bytes (see WithRand),
// encoded with unpadded URL-safe base64, 27 characters. Make a new one
// for each Response, and use it with saml.TransientNameIDFormat. Unlike
// the user's ID, it tells the SP nothing that it could match against the
// NameIDs other SPs receive, or against those of the user's other logins.
// The SP may later send it back, in a LogoutRequest for example: to map it
// back to the user, keep it with the user's IdP session.
//
// It panics if the source of random bytes fails, as crypto/rand never
// does.
func (c *Config) TransientNameID() string {
	b := make([]byte, transientNameIDBytes)
	if _, err := io.ReadFull(c.Rand(), b); err != nil {
		panic(fmt.Sprintf("samlidp: reading random bytes for a transient NameID: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// PairwiseNameID returns a persistent NameID (saml-core §8.3.7) for the
// user userID at the service provider spEntityID, or rather in the
// namespace spEntityID names: the SP's own entity ID, or the ID of an
// affiliation of SPs that are to share the NameID (see
// Config.PairwiseNameIDFor, which chooses it). The NameID is the
// HMAC-SHA256, under key, of a fixed label and of userID and spEntityID,
// each preceded by its length, so that no two pairs of inputs are
// encoded alike; it is encoded with unpadded URL-safe base64, 43
// characters.
//
// The same inputs always give the same NameID, so there is nothing to
// store; different SPs (or affiliations) get unrelated NameIDs, which
// they cannot correlate, nor turn back into userID, without the key
// (saml-core §8.3.7 asks for exactly this: an opaque identifier, distinct
// for each SP, that does not reveal the user's ID).
//
// The key must be secret, random, and at least MinPairwiseKeySize bytes:
// PairwiseNameID panics if it is shorter. Whoever has it can link the
// NameIDs of a user across SPs, and can compute the NameID of any user
// for any SP. It must also be stable: every NameID depends on it, so a
// new key gives every user a new NameID at every SP, which then no longer
// recognizes its users. Keep it with the IdP's other long-term secrets,
// not with its rotating keys, and do not rotate it as a matter of course.
// To change it without losing users, keep the NameIDs made under the old
// key, and issue those to the SPs that already know them. Use the key for
// nothing else; userID must be an ID that the user keeps, not one, such
// as an email address, that may change or be given to someone else.
func PairwiseNameID(key []byte, userID, spEntityID string) string {
	if len(key) < MinPairwiseKeySize {
		panic(fmt.Sprintf("samlidp: the pairwise NameID key is %d bytes; it must be at least %d", len(key), MinPairwiseKeySize))
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(pairwiseDomain))
	for _, s := range []string{userID, spEntityID} {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		mac.Write(n[:])
		mac.Write([]byte(s))
	}
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// PairwiseNameIDFor returns the PairwiseNameID of the user userID for the
// SP of req, in the namespace that Response qualifies the NameID with: the
// SPNameQualifier of the request's NameIDPolicy, if any, and the SP's
// entity ID otherwise (saml-core §3.4.1.1, §8.3.7). So an SP that asks
// for the SPNameQualifier of an affiliation it is a member of, as
// WithAffiliation decides, gets the NameID that every other member asking
// for it gets; one that does not ask gets a NameID of its own. An SP
// that asks for an affiliation WithAffiliation does not allow is refused,
// as Response would refuse it: the error matches *saml.StatusError, to
// send with ErrorResponse. If the Config's saml.IdentityProvider does not
// enforce the NameIDPolicy, the SPNameQualifier is ignored, as Response
// ignores it, and the SP gets a NameID of its own.
//
// See PairwiseNameID for what the key must be.
func (c *Config) PairwiseNameIDFor(ctx context.Context, req *AuthnRequest, key []byte, userID string) (string, error) {
	idp := c.identityProvider(nil)
	if err := c.spNameQualifierError(ctx, idp, req); err != nil {
		return "", err
	}
	namespace := req.ServiceProvider
	if idp.EnforceNameIDPolicy && req.SPNameQualifier != "" {
		namespace = req.SPNameQualifier
	}
	return PairwiseNameID(key, userID, namespace), nil
}

// SetNameID sets the NameID and NameIDFormat of subject for the user
// userID and the SP of req, so that SPs cannot correlate the user by it:
// a new TransientNameID, with saml.TransientNameIDFormat, if req asks for
// the transient format, and otherwise the PairwiseNameIDFor of userID,
// with saml.PersistentNameIDFormat. An SP that asks for another format,
// such as an email address, is then refused by Response, with
// StatusInvalidNameIDPolicy; to send it something else, set the NameID
// yourself.
//
// A pairwise NameID is computed, not created, so SetNameID cannot tell
// whether the SP has seen it before: if the application records the SPs
// each user has logged in to, it should answer a request whose
// AllowCreate is false, from an SP the user has not logged in to, with
// StatusInvalidNameIDPolicy rather than calling SetNameID.
func (c *Config) SetNameID(ctx context.Context, req *AuthnRequest, subject *Subject, key []byte, userID string) error {
	if req.NameIDFormat == saml.TransientNameIDFormat {
		subject.NameID = c.TransientNameID()
		subject.NameIDFormat = saml.TransientNameIDFormat
		return nil
	}
	nameID, err := c.PairwiseNameIDFor(ctx, req, key, userID)
	if err != nil {
		return err
	}
	subject.NameID = nameID
	subject.NameIDFormat = saml.PersistentNameIDFormat
	return nil
}
