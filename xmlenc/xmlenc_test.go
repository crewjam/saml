package xmlenc

import (
	"io/ioutil"
	"math/rand"
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
)

func TestDataAES128CBC(t *testing.T) {
	RandReader = rand.New(rand.NewSource(0)) // deterministic random numbers for tests
	plaintext, err := ioutil.ReadFile("test_data/encrypt-data-aes128-cbc.data")
	assert.NoError(t, err)

	var ciphertext string
	{
		encrypter := AES128CBC
		cipherEl, encErr := encrypter.Encrypt([]byte("abcdefghijklmnop"), []byte(plaintext))
		assert.NoError(t, encErr)

		doc := etree.NewDocument()
		doc.SetRoot(cipherEl)
		doc.IndentTabs()
		ciphertext, err = doc.WriteToString()
		assert.NoError(t, err)
	}

	{
		decrypter := AES128CBC
		doc := etree.NewDocument()
		err = doc.ReadFromString(ciphertext)
		assert.NoError(t, err)

		actualPlaintext, err := decrypter.Decrypt(
			[]byte("abcdefghijklmnop"), doc.Root())
		assert.NoError(t, err)
		assert.Equal(t, plaintext, actualPlaintext)
	}

	{
		decrypter := AES128CBC
		doc := etree.NewDocument()
		err := doc.ReadFromFile("test_data/encrypt-data-aes128-cbc.xml")
		assert.NoError(t, err)

		actualPlaintext, err := decrypter.Decrypt([]byte("abcdefghijklmnop"), doc.Root())
		assert.NoError(t, err)
		assert.Equal(t, plaintext, actualPlaintext)
	}
}

/*
func TestAES256CBC(t *testing.T) {
	RandReader = rand.New(rand.NewSource(0)) // deterministic random numbers for tests
	doc := etree.NewDocument()
	err := doc.ReadFromFile("test_data/plaintext.xml")
	assert.NoError(t, err)

	el := doc.FindElement("//PaymentInfo")
	assert.NotNil(t, el)

	tmpDoc := etree.NewDocument()
	tmpDoc.SetRoot(el.Copy())
	tmpBuf, _ := tmpDoc.WriteToString()

	encrypter := AES256CBC
	cipherEl, err := encrypter.Encrypt(
		[]byte("abcdefghijklmnopqrstuvwxyz012345"), []byte(tmpBuf))
	assert.NoError(t, err)

	el.Child = nil
	el.AddChild(cipherEl)

	doc.IndentTabs()
	s, _ := doc.WriteToString()
	fmt.Println(s)
}
*/
