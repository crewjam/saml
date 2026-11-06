//go:build gofuzz
// +build gofuzz

package xmlenc

import (
	"testing"

	"strings"
)

var testKey = func() *rsa.PrivateKey {
	//nolint:gosec
	const keyStr = `-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDkXTUsWzRVpUHjbDpWCfYDfXmQ/q4LkaioZoTpu4ut1Q3eQC5t
gD14agJhgT8yzeY5S/YNlwCyuVkjuFyoyTHFX2IOPpz7jnh4KnQ+B1IH9fY/+kmk
zHJgxSUDJsdUMPgGpKt5hnEn7ziXAWXLc2udFbnHwhi9TXXwRHGi9wZ4YwIDAQAB
AoGBALNTnlXeqRI4W61DZ+v4ln/XIIeD9xiOoWrcVrNU2zL+g41ryQmkEqFkXcpD
vGUg2xFTXTz+v0WZ1y39sIW6uKFRYUfaNsF6iVfGAyx1VWK/jgtPnCWDQy26Eby0
BqpbZRy1a6MLYVEG/5bvZE01CDV4XttpTrNX91WWcYGduJxBAkEA6ED1ZOqIzBpu
c2KAo+bWmroCH8+cSDk0gVq6bnRB+EEhRCmo/VgvndWLxfexdGmDIOAIisB06N5a
GzBSCaEY/QJBAPu2cNvuuBNLwrlxPCwOEpIHYT4gJq8UMtg6O6N+u++nYCGhK6uo
VCmrKY+UewyNIcsLZF0jsNI2qJjiU1vQxN8CQQDfQJnigMQwlfO3/Ga1po6Buu2R
0IpkroB3G1R8GkrTrR+iGv2zUdKrwHsUOC2fPlFrB4+OeMOomRw6aG9jjDStAkB1
ztiZhuvuVAoKIv5HnDqC0CNqIUAZtzlozDB3f+xT6SFr+/Plfn4Nlod4JMVGhZNo
ZaeOlBLBAEX+cAcVtOs/AkBicZOAPv84ABmFfyhXhYaAuacaJLq//jg+t+URUOg+
XZS9naRmawEQxOkZQVoMeKgvu05+V4MniFqdQBINIkr5
-----END RSA PRIVATE KEY-----`
	b, _ := pem.Decode([]byte(keyStr))
	k, err := x509.ParsePKCS1PrivateKey(b.Bytes)
	if err != nil {
		panic(err)
	}
	return k
}()

func TestPastFuzzingFailures(t *testing.T) {
	entries, err := io.ReadDir("crashers")
	if err != nil {
		t.Errorf("%s", err)
		return
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".output") {
			continue
		}
		if strings.HasSuffix(entry.Name(), ".quoted") {
			continue
		}
		t.Logf("%s", entry.Name())
		data, err := io.ReadFile("crashers/" + entry.Name())
		if err != nil {
			t.Errorf("%s: %s", entry.Name(), err)
			return
		}
		Fuzz(testKey, data)
	}
}
