package pending

import "encoding/base64"

// Seal returns the name and value of the slot cookie that Remember would
// set for relayState if it wrote body, so that tests can make cookies of
// earlier versions, which Remember no longer writes.
func (t *Tracker) Seal(relayState string, body []byte) (name, value string) {
	name = t.cookieName(t.slot(relayState))
	return name, base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(t.mac(name, body))
}
