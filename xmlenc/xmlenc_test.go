package xmlenc

import (
	"io/ioutil"
	"math/rand"

	"github.com/beevik/etree"
	. "gopkg.in/check.v1"
)

type TestFoo struct {
}

var _ = Suite(&TestFoo{})

func (test *TestFoo) SetUpTest(c *C) {
	RandReader = rand.New(rand.NewSource(0)) // deterministic random numbers for tests
}

func (test *TestFoo) TestDataAES128CBC(c *C) {
	plaintext, err := ioutil.ReadFile("test_data/encrypt-data-aes128-cbc.data")
	c.Assert(err, IsNil)

	var ciphertext string
	{
		encrypter := AES128CBC
		cipherEl, encErr := encrypter.Encrypt([]byte("abcdefghijklmnop"), []byte(plaintext))
		c.Assert(encErr, IsNil)

		doc := etree.NewDocument()
		doc.SetRoot(cipherEl)
		doc.IndentTabs()
		ciphertext, err = doc.WriteToString()
		c.Assert(err, IsNil)
	}

	{
		decrypter := AES128CBC
		doc := etree.NewDocument()
		err = doc.ReadFromString(ciphertext)
		c.Assert(err, IsNil)

		actualPlaintext, err := decrypter.Decrypt(
			[]byte("abcdefghijklmnop"), doc.Root())
		c.Assert(err, IsNil)
		c.Assert(actualPlaintext, DeepEquals, plaintext)
	}

	{
		decrypter := AES128CBC
		doc := etree.NewDocument()
		err := doc.ReadFromFile("test_data/encrypt-data-aes128-cbc.xml")
		c.Assert(err, IsNil)

		actualPlaintext, err := decrypter.Decrypt([]byte("abcdefghijklmnop"), doc.Root())
		c.Assert(err, IsNil)
		c.Assert(actualPlaintext, DeepEquals, plaintext)
	}
}

/*
func (test *TestFoo) TestAES256CBC(c *C) {
	doc := etree.NewDocument()
	err := doc.ReadFromFile("test_data/plaintext.xml")
	c.Assert(err, IsNil)

	el := doc.FindElement("//PaymentInfo")
	c.Assert(el, Not(IsNil))

	tmpDoc := etree.NewDocument()
	tmpDoc.SetRoot(el.Copy())
	tmpBuf, _ := tmpDoc.WriteToString()

	encrypter := AES256CBC
	cipherEl, err := encrypter.Encrypt(
		[]byte("abcdefghijklmnopqrstuvwxyz012345"), []byte(tmpBuf))
	c.Assert(err, IsNil)

	el.Child = nil
	el.AddChild(cipherEl)

	doc.IndentTabs()
	s, _ := doc.WriteToString()
	fmt.Println(s)
}
*/
