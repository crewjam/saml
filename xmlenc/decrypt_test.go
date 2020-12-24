package xmlenc

import (
	"crypto/x509"
	"encoding/pem"
	"gotest.tools/golden"
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
)

func TestCanDecrypt(t *testing.T) {
	doc := etree.NewDocument()
	err := doc.ReadFromString(string(golden.Get(t, "input.xml")))
	assert.NoError(t, err)

	keyPEM := "-----BEGIN RSA PRIVATE KEY-----\nMIICXgIBAAKBgQDU8wdiaFmPfTyRYuFlVPi866WrH/2JubkHzp89bBQopDaLXYxi\n3PTu3O6Q/KaKxMOFBqrInwqpv/omOGZ4ycQ51O9I+Yc7ybVlW94lTo2gpGf+Y/8E\nPsVbnZaFutRctJ4dVIp9aQ2TpLiGT0xX1OzBO/JEgq9GzDRf+B+eqSuglwIDAQAB\nAoGBAMuy1eN6cgFiCOgBsB3gVDdTKpww87Qk5ivjqEt28SmXO13A1KNVPS6oQ8SJ\nCT5Azc6X/BIAoJCURVL+LHdqebogKljhH/3yIel1kH19vr4E2kTM/tYH+qj8afUS\nJEmArUzsmmK8ccuNqBcllqdwCZjxL4CHDUmyRudFcHVX9oyhAkEA/OV1OkjM3CLU\nN3sqELdMmHq5QZCUihBmk3/N5OvGdqAFGBlEeewlepEVxkh7JnaNXAXrKHRVu/f/\nfbCQxH+qrwJBANeQERF97b9Sibp9xgolb749UWNlAdqmEpmlvmS202TdcaaT1msU\n4rRLiQN3X9O9mq4LZMSVethrQAdX1whawpkCQQDk1yGf7xZpMJ8F4U5sN+F4rLyM\nRq8Sy8p2OBTwzCUXXK+fYeXjybsUUMr6VMYTRP2fQr/LKJIX+E5ZxvcIyFmDAkEA\nyfjNVUNVaIbQTzEbRlRvT6MqR+PTCefC072NF9aJWR93JimspGZMR7viY6IM4lrr\nvBkm0F5yXKaYtoiiDMzlOQJADqmEwXl0D72ZG/2KDg8b4QZEmC9i5gidpQwJXUc6\nhU+IVQoLxRq0fBib/36K9tcrrO5Ba4iEvDcNY+D8yGbUtA==\n-----END RSA PRIVATE KEY-----\n"
	b, _ := pem.Decode([]byte(keyPEM))
	key, err := x509.ParsePKCS1PrivateKey(b.Bytes)
	assert.NoError(t, err)

	el := doc.Root().FindElement("//EncryptedKey")
	buf, err := Decrypt(key, el)
	assert.NoError(t, err)
	assert.Equal(t,
		[]byte{0xc, 0x70, 0xa2, 0xc8, 0x15, 0x74, 0x89, 0x3f, 0x36, 0xd2, 0x7c, 0x14, 0x2a, 0x9b, 0xaa, 0xd9},
		buf)

	el = doc.Root().FindElement("//EncryptedData")
	buf, err = Decrypt(key, el)
	assert.NoError(t, err)
	assert.Equal(t, string(golden.Get(t, "plaintext.xml")), string(buf))
}

func TestCanDecryptWithoutCertificate(t *testing.T) {
	doc := etree.NewDocument()
	err := doc.ReadFromString(string(golden.Get(t, "input.xml")))
	assert.NoError(t, err)

	el := doc.FindElement("//ds:X509Certificate")
	el.Parent().RemoveChild(el)

	keyPEM := golden.Get(t, "key.pem")
	b, _ := pem.Decode(keyPEM)
	key, err := x509.ParsePKCS1PrivateKey(b.Bytes)
	assert.NoError(t, err)

	el = doc.Root().FindElement("//EncryptedKey")
	buf, err := Decrypt(key, el)
	assert.NoError(t, err)
	assert.Equal(t, []byte{0xc, 0x70, 0xa2, 0xc8, 0x15, 0x74, 0x89, 0x3f, 0x36, 0xd2, 0x7c, 0x14, 0x2a, 0x9b, 0xaa, 0xd9}, buf)

	el = doc.Root().FindElement("//EncryptedData")
	buf, err = Decrypt(key, el)
	assert.NoError(t, err)
	assert.Equal(t, string(golden.Get(t, "plaintext.xml")), string(buf))
}
