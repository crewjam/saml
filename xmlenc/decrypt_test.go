package xmlenc

import (
	"crypto/x509"
	"encoding/pem"
	"testing"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
	"gotest.tools/golden"

	"github.com/beevik/etree"
)

func TestCanDecrypt(t *testing.T) {
	t.Run("CBC", func(t *testing.T) {
		doc := etree.NewDocument()
		err := doc.ReadFromBytes(golden.Get(t, "input.xml"))
		assert.Check(t, err)

		keyPEM := "-----BEGIN RSA PRIVATE KEY-----\nMIICXgIBAAKBgQDU8wdiaFmPfTyRYuFlVPi866WrH/2JubkHzp89bBQopDaLXYxi\n3PTu3O6Q/KaKxMOFBqrInwqpv/omOGZ4ycQ51O9I+Yc7ybVlW94lTo2gpGf+Y/8E\nPsVbnZaFutRctJ4dVIp9aQ2TpLiGT0xX1OzBO/JEgq9GzDRf+B+eqSuglwIDAQAB\nAoGBAMuy1eN6cgFiCOgBsB3gVDdTKpww87Qk5ivjqEt28SmXO13A1KNVPS6oQ8SJ\nCT5Azc6X/BIAoJCURVL+LHdqebogKljhH/3yIel1kH19vr4E2kTM/tYH+qj8afUS\nJEmArUzsmmK8ccuNqBcllqdwCZjxL4CHDUmyRudFcHVX9oyhAkEA/OV1OkjM3CLU\nN3sqELdMmHq5QZCUihBmk3/N5OvGdqAFGBlEeewlepEVxkh7JnaNXAXrKHRVu/f/\nfbCQxH+qrwJBANeQERF97b9Sibp9xgolb749UWNlAdqmEpmlvmS202TdcaaT1msU\n4rRLiQN3X9O9mq4LZMSVethrQAdX1whawpkCQQDk1yGf7xZpMJ8F4U5sN+F4rLyM\nRq8Sy8p2OBTwzCUXXK+fYeXjybsUUMr6VMYTRP2fQr/LKJIX+E5ZxvcIyFmDAkEA\nyfjNVUNVaIbQTzEbRlRvT6MqR+PTCefC072NF9aJWR93JimspGZMR7viY6IM4lrr\nvBkm0F5yXKaYtoiiDMzlOQJADqmEwXl0D72ZG/2KDg8b4QZEmC9i5gidpQwJXUc6\nhU+IVQoLxRq0fBib/36K9tcrrO5Ba4iEvDcNY+D8yGbUtA==\n-----END RSA PRIVATE KEY-----\n"
		b, _ := pem.Decode([]byte(keyPEM))
		key, err := x509.ParsePKCS1PrivateKey(b.Bytes)
		assert.Check(t, err)

		el := doc.Root().FindElement("//EncryptedKey")
		buf, err := Decrypt(key, el)
		assert.Check(t, err)
		assert.Check(t, is.DeepEqual([]byte{0xc, 0x70, 0xa2, 0xc8, 0x15, 0x74, 0x89, 0x3f, 0x36, 0xd2, 0x7c, 0x14, 0x2a, 0x9b, 0xaa, 0xd9},
			buf))

		el = doc.Root().FindElement("//EncryptedData")
		buf, err = Decrypt(key, el)
		assert.Check(t, err)
		golden.Assert(t, string(buf), "plaintext.xml")
	})

	t.Run("GCM", func(t *testing.T) {
		doc := etree.NewDocument()
		err := doc.ReadFromBytes(golden.Get(t, "input_gcm.xml"))
		assert.Check(t, err)

		keyPEM := golden.Get(t, "cert.key")
		b, _ := pem.Decode(keyPEM)
		key, err := x509.ParsePKCS8PrivateKey(b.Bytes)
		assert.Check(t, err)

		el := doc.Root().FindElement("//EncryptedKey")
		_, err = Decrypt(key, el)
		assert.Check(t, err)

		el = doc.Root().FindElement("//EncryptedData")
		_, err = Decrypt(key, el)
		assert.Check(t, err)
	})
}

func TestCanDecryptWithoutCertificate(t *testing.T) {
	t.Run("CBC", func(t *testing.T) {
		doc := etree.NewDocument()
		err := doc.ReadFromBytes(golden.Get(t, "input.xml"))
		assert.Check(t, err)

		el := doc.FindElement("//ds:X509Certificate")
		el.Parent().RemoveChild(el)

		keyPEM := golden.Get(t, "key.pem")
		b, _ := pem.Decode(keyPEM)
		key, err := x509.ParsePKCS1PrivateKey(b.Bytes)
		assert.Check(t, err)

		el = doc.Root().FindElement("//EncryptedKey")
		buf, err := Decrypt(key, el)
		assert.Check(t, err)
		assert.Check(t, is.DeepEqual([]byte{0xc, 0x70, 0xa2, 0xc8, 0x15, 0x74, 0x89, 0x3f, 0x36, 0xd2, 0x7c, 0x14, 0x2a, 0x9b, 0xaa, 0xd9}, buf))

		el = doc.Root().FindElement("//EncryptedData")
		buf, err = Decrypt(key, el)
		assert.Check(t, err)
		golden.Assert(t, string(buf), "plaintext.xml")
	})

	t.Run("GCM", func(t *testing.T) {
		doc := etree.NewDocument()
		err := doc.ReadFromBytes(golden.Get(t, "input_gcm.xml"))
		assert.Check(t, err)

		el := doc.FindElement("//ds:X509Certificate")
		el.Parent().RemoveChild(el)

		keyPEM := golden.Get(t, "cert.key")
		b, _ := pem.Decode(keyPEM)
		key, err := x509.ParsePKCS8PrivateKey(b.Bytes)
		assert.Check(t, err)

		el = doc.Root().FindElement("//EncryptedKey")
		_, err = Decrypt(key, el)
		assert.Check(t, err)

		el = doc.Root().FindElement("//EncryptedData")
		_, err = Decrypt(key, el)
		assert.Check(t, err)
	})
}
