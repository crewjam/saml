package saml

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"

	"os"

	"github.com/beevik/etree"
	"github.com/crewjam/saml/logger"
	"github.com/crewjam/saml/testsaml"
	"github.com/crewjam/saml/xmlenc"
	"github.com/dgrijalva/jwt-go"
	. "gopkg.in/check.v1"
)

type IdentityProviderTest struct {
	SPKey         *rsa.PrivateKey
	SPCertificate *x509.Certificate
	SP            ServiceProvider

	Key             crypto.PrivateKey
	Certificate     *x509.Certificate
	SessionProvider SessionProvider
	IDP             IdentityProvider
}

var _ = Suite(&IdentityProviderTest{})

func mustParseURL(s string) url.URL {
	rv, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return *rv
}

func mustParsePrivateKey(pemStr string) crypto.PrivateKey {
	b, _ := pem.Decode([]byte(pemStr))
	if b == nil {
		panic("cannot parse PEM")
	}
	k, err := x509.ParsePKCS1PrivateKey(b.Bytes)
	if err != nil {
		panic(err)
	}
	return k
}

func mustParseCertificate(pemStr string) *x509.Certificate {
	b, _ := pem.Decode([]byte(pemStr))
	if b == nil {
		panic("cannot parse PEM")
	}
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		panic(err)
	}
	return cert
}

func (test *IdentityProviderTest) SetUpTest(c *C) {
	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05 MST 2006", "Mon Dec 1 01:57:09 UTC 2015")
		return rv
	}
	jwt.TimeFunc = TimeNow
	RandReader = &testRandomReader{}                // TODO(ross): remove this and use the below generator
	xmlenc.RandReader = rand.New(rand.NewSource(0)) // deterministic random numbers for tests

	//test.AuthnRequest = `https://idp.testshib.org/idp/profile/SAML2/Redirect/SSO?RelayState=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1cmkiOiIvIn0.eoUmy2fQduAz--6N82xIOmufY1ZZeRi5x--B7m1pNIY&SAMLRequest=lJJBj9MwEIX%2FSuR7Yzt10sZKIpWtkCotsGqB%2B5BMW4vELp4JsP8et4DYE5Tr%2BPnN957dbGY%2B%2Bz1%2BmZE4%2Bz6NnloxR28DkCPrYUKy3NvD5s2jLXJlLzFw6MMosg0RRnbBPwRP84TxgPGr6%2FHD%2FrEVZ%2BYLWSl1WVXaGJP7UwyfcxckwTQWEnoS2TbtdB6uHn9uuOGSczqgs%2FuUh3i6DmTaenQjyitGIfc4uIg9y8Phnch221a4YVFjpVflcqgM1sUajiWsYGk01KujKVRfJyHRjDtPDJ5bUShdLrReLNX7QtmysrrMK6Pqem3MeqFKq5TInn6lfeX84PypFSL7iJFuwKkN0TU303hPc%2FC7L5G9DnEC%2Frv8OkmxjjepRc%2BOn0X3r14nZBiAoZE%2FwbrmbfLZbZ%2FC6Prn%2F3zgcQzfHiICYys4zii6%2B4E5gieXsBv5kqBr5Msf1%2F0IAAD%2F%2Fw%3D%3D`
	//test.SamlResponse = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><saml2p:Response xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\" Destination=\"https://15661444.ngrok.io/saml2/acs\" ID=\"_e9b3332eeaf348da6786aed16300aca9\" InResponseTo=\"id-9e61753d64e928af5a7a341a97f420c9\" IssueInstant=\"2015-12-01T01:56:21.375Z\" Version=\"2.0\"><saml2:Issuer xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">https://idp.testshib.org/idp/shibboleth</saml2:Issuer><saml2p:Status><saml2p:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></saml2p:Status><saml2:EncryptedAssertion xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\"><xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" Id=\"_dab0b1dbbc0595ab06473034e3bb798c\" Type=\"http://www.w3.org/2001/04/xmlenc#Element\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\" xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"/><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><xenc:EncryptedKey Id=\"_dd9264352cef16103cdb21fae97fa951\" xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\" xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"/></xenc:EncryptionMethod><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIB7zCCAVgCCQDFzbKIp7b3MTANBgkqhkiG9w0BAQUFADA8MQswCQYDVQQGEwJVUzELMAkGA1UE\nCAwCR0ExDDAKBgNVBAoMA2ZvbzESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTEzMTAwMjAwMDg1MVoX\nDTE0MTAwMjAwMDg1MVowPDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkdBMQwwCgYDVQQKDANmb28x\nEjAQBgNVBAMMCWxvY2FsaG9zdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA1PMHYmhZj308\nkWLhZVT4vOulqx/9ibm5B86fPWwUKKQ2i12MYtz07tzukPymisTDhQaqyJ8Kqb/6JjhmeMnEOdTv\nSPmHO8m1ZVveJU6NoKRn/mP/BD7FW52WhbrUXLSeHVSKfWkNk6S4hk9MV9TswTvyRIKvRsw0X/gf\nnqkroJcCAwEAATANBgkqhkiG9w0BAQUFAAOBgQCMMlIO+GNcGekevKgkakpMdAqJfs24maGb90Dv\nTLbRZRD7Xvn1MnVBBS9hzlXiFLYOInXACMW5gcoRFfeTQLSouMM8o57h0uKjfTmuoWHLQLi6hnF+\ncvCsEFiJZ4AbF+DgmO6TarJ8O05t8zvnOwJlNCASPZRH/JmF8tX0hoHuAQ==</ds:X509Certificate></ds:X509Data></ds:KeyInfo><xenc:CipherData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"><xenc:CipherValue>i/wh2ubXbhTH5W3hwc5VEf4DH1xifeTuxoe64ULopGJ0M0XxBKgDEIfTg59JUMmDYB4L8UStTFfqJk9BRGcMeYWVfckn5gCwLptD9cz26irw+7Ud7MIorA7z68v8rEyzwagKjz8VKvX1afgec0wobVTNN3M1Bn+SOyMhAu+Z4tE=</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"><xenc:CipherValue>a6PZohc8i16b2HG5irLqbzAt8zMI6OAjBprhcDb+w6zvjU2Pi9KgGRBAESLKmVfBR0Nf6C/cjozCGyelfVMtx9toIV1C3jtanoI45hq2EZZVprKMKGdCsAbXbhwYrd06QyGYvLjTn9iqako6+ifxtoFHJOkhMQShDMv8l3p5n36iFrJ4kUT3pSOIl4a479INcayp2B4u9MVJybvN7iqp/5dMEG5ZLRCmtczfo6NsUmu+bmT7O/Xs0XeDmqICrfI3TTLzKSOb8r0iZOaii5qjfTALDQ10hlqxV4fgd51FFGG7eHr+HHD+FT6Q9vhNjKd+4UVT2LZlaEiMw888vyBKtfl6gTsuJbln0fHRPmOGYeoJlAdfpukhxqTbgdzOke2NY5VLw72ieUWREAEdVXBolrzbSaafumQGuW7c8cjLCDPOlaYIvWsQzQOp5uL5mw4y4S7yNPtTAa5czcf+xgw4MGatcWeDFv0gMTlnBAGIT+QNLK/+idRSpnYwjPO407UNNa2HSX3QpZsutbxyskqvuMgp08DcI2+7+NrTXtQjR5knhCwRNkGTOqVxEBD6uExSjbLBbFmd4jgKn73SqHStk0wCkKatxbZMD8YosTu9mrU2wuWacZ1GFRMlk28oaeXl9qUDnqBwZ5EoxT/jDjWIMWw9b40InvZK6kKzn+v3BSGKqzq2Ecj9yxE7u5/51NC+tFyZiN2J9Lu9yehvW46xRrqFWqCyioFza5bw1yd3bzkuMMpd6UvsZPHKvWwap3+O6ngc8bMBBCLltJVOaTn/cBGsUvoARY6Rfftsx7BamrfGURd8vqq+AI6Z1OC8N3bcRCymIzw0nXdbUSqhKWwbw6P2szvAB6kCdu4+C3Bo01CEQyerCCbpfn/cZ+rPsBVlGdBOLl5eCW8oJOODruYgSRshrTnDffLQprxCddj7vSnFbVHirU8a0KwpCVCdAAL9nKppTHs0Mq2YaiMDo8mFvx+3kan/IBnJSOVL19vdLfHDbZqVh7UVFtiuWv3T15BoiefDdF/aR5joN0zRWf8l6IYcjBOskk/xgxOZhZzbJl8DcgTawD8giJ31SJ1NoOqgrSD4wBHGON4mInHkO0X5+vw1jVNPGF3BwHw0kxoCT3ZKdSsi8O4tlf1y227cf794AGnyQe13O032jYgOmM5qNkET6PyfkyD/h0ufgQq2vJvxSOiRv76Kdg0SeRuNPW9MyjO/5APHl7tBlDBEVq+LWDHl4g9h/bw+Fsi0WN4pLN1Yv9RANWpIsXWyvxTWIZHTuZEjNbHqFKpsefx/oY1b9cSzKR5fQ9vc32e17WykL0O7pwpzV6TrFN874GdmW5lG5zfqnRHUQh1aV2WwBJ74mB4tv/y5rmRjTe5h/rN90kN+eQGeR3eG7XUHLhK/yCV+xq8KKPxNZexcdHGA905rvYokbtmr/jIN5kAMBdlOU8akPAZdSMMh+g/RZo5MO50/gdg6MTpB4onU2FBd54FNDp2fuBUxBsnTqpZXkDcAPEfSBr+z2l8jTRmxMricWyeC55ILgxM4er68n0xYjwb2jyQum3IQq7TSYYU/qjNiH1fQBtdRmBkzXJYYk+9q7C6OZJUdR96ERnTIi93NaYmtpSEvZU9vS6MV1VBOnEf8UzUUT9ibMpP9XDSINX7dN24rKIufSY+3+70orQB07XOWp6++SWKgA+WThaoPhp8sWWMeSZuda/wq6jdVTAB8FOPiP3lNl0BqxagQEPmNxDWXwTplSFSR3SP0e4sHMSjLvysibV9Z87LZa1FG0cWU2hrhiyOLsIWMnd4vdTLaWjhXuGlrDShxSAiI39wsl5RB59E+DXVSTBQAoAkHCKGK69YiMKU9K8K/LeodApgw46oPL08EWvleKPCbdTyjKUADtxfAujR84GMEUz9Aml4Q497MfvABQOW6Hwg54Z3UbwLczDCOZyK1wIwZTyS9w3eTH/6EBeyzhtt4G2e/60jkywHOKn17wQgww2ZsDcukdsCMfo4FV0NzfhSER8BdL+hdLJS3R1F/Vf4aRBEuOuycv2AqB1ZqHhcjZh7yDv0RpBvn3+2rzfzmYIBlqL16d1aBnvL4C03I0J59AtXN9WlfJ8SlJhrduW/PF4pSCAQEyHGprP9hVhaXCOUuXCbjA2FI57NkxALQ2HpCVpXKGw0qO0rYxRYIRlKTl43VFcrSGJdVYOFUk0ZV3b+k+KoxLVSgBjIUWxio/tvVgUYDZsO3M3x0I+0r9xlWZSFFmhwdOFouD+Xy1NPTmgwlUXqZ4peyIE1oVntpcrTJuev2jNScXbU9PG8b589GM4Z09KS/fAyytTFKmUpBuTme969qu0eA7/kBSHAkKvbfj0hsrbkkF9y/rXi8xgcMXNgYayW8MHEhm506AyPIvJAreZL637/BENO1ABdWS1Enj/uGaLM1ED8UY94boh/lMhqa9jALgEOHHxspavexi3HIFwJ55s4ocQnjb4p6op4CRPUdPCfli5st9m3NtQoH9kT1FTRZa9sG8Ybhey5wP17YgPIg9ZZtvlvpSTwCwZxHZ348wXJWhbtId9DyOcIzsyK5HaJcRsp8SQVR5nbRW0pUyC/bFAtX1KOGJmtro/QfmnLG9ksuaZvxP6+bH1K+CibEFIRDllAUFFPiuT+2b3Yp3Tu1VvXokMAgmcB5iFDgTAglw5meJYJ99uIBmj0EVZm8snMhRrHjMPTAYD5kwPK/YDShPFFV3XEIFzLD3iYrzb7sub/Z4gTTELWzzS3bCpYPAh4KWeTih+p7Xj0Xf04nSONHZXsQnNenc+PNae+Zj5iCfJ/PpqhMn61n/YBP7gipYYEtOZYzDtvMz+mytYRUOaZTq3W4Wp64f+XVekn49CLarLm6qPyiz5kJwaT8lJ+VEZDPpS/ChLM4eq90GogJBvK0jxmQ1AGvnKpV2lw9XCudf3PXbaTb+r2QPcihKnmqcEgPgYlN8VLclicNW1WyjBJ+HvDTQPbs1r1/KnBK4O5HTT6ehuHpJsYlBN9vzjsD+ov6SRkBqiGPUg9CoKKmWS6dirxwOXi3OUFzkWFVDyDezfkJAzqkmG0nlEGb9mTHdVDfX010bPJ4ZQzQSyHp7Ht2mATyQwOEem2AMB/RpNwlOKXWIdsQ5p3dHF+kmsJHI8xjEv2GeUa/aXX3MF3fPfUA7La8J8fbnaDLbnEqMCLMfdfc9+kY7EKyqPiE5KFpF0EhQBrHl8SiPuFQCoxvlH2u+ujncW7Z5JiBmMKUWOXUHhIe4NckP1awRsEcfhEs664DqOp9CbLwTXk71hHVBtINylFcf7uBZwjxNW+hCfZEoVEjjs/V4J9QeXCxpTu5TcXxBxwN5zBdkCodNFPLUg+3UicaykaH0+wrGoTu/ugjF9rz7OezMMs3pep+bzLp+yZbFAL/z/yATY3UG+lpk6Rw4SkjbnAxBSedaEdqbotddkGzVQubHvHqCiKpkAw58rAa2v15hc+UmkrRFslS8SYxTIPXs2sTNhnCCrUn8nlKufeoAm65vgYtEQ4NzmG9tqKtTeBfZAvSToYaiQq+kPii1ssuu1OULAVuSx8x/CYO6orgX7h5wI0R/Ug1nux7cb2/+pFLbNyGvwKf1TLym2NvFMJpvFlTsOJJ4DxXM/v2JkC9umm93quXLsojx7KTEOFDQLsnMKsVo6ZzRQidEwK5gQPyZL1yjGirJcEuGMAEf6LA2AsKIIZhsMEPlLpzMiVo5Y0LoL6NFsXigceLaaJMEMuYNJJdh+uxyfW57+PoQ7V8KkzSHFsKan14GnpWeOV7r13uopwCPeIsEKUVG77ypd+ILQkbKxH2lQdsFyjpofqkbgEVM5XAnVbdhfwyebNHn5OJtadVkOMcJc/WMWJef1idcSfvP5ENkwp3pKg9Ljoi+hU2Chp1vTmksO2HJt0of4QnQ8jGlcqnOrAMiWUCd2W/8AmhRBjevt3UqxnqELVvg+HJPlyqFyuUlDxx25mXEdW0COpA3s9OlSgcMjvQbIJ42NUhGFZLoK1pvPLZo711w2Ex3Lm5qqcr/7I4+vTntd/Id5aJiP18LQpslTy614Wd4eD8+RfjEtmDAPXhgvfekVkS/rDnI/9H0k3AdHc78fJCJRPNwJrDTozzjxTvmVv9r4MtpoDELmnMxb3o7ZibUMxgptCTyDF+Q5m6T3GeD9G5ehgB3Tqsx3gcUGuDtP6KIqMGbj8YCFt8tjihDctYFAXj4AwPnIjMiI4T7skXwfrBLWCKfN1j5XrIn2paQgKln9hvaiRUpNpD3IXVyFl1WNrb21IcRinfkuCtrP2tTHqct6eSEh8sOzRkvZEArBQYD5paYyuNBcbVtsnl6PNE+DIcSIGvCVnzpMw1BeUExvQZoNdpHwhTQ3FSd1XN1nt0EWx6lve0Azl/zJBhj5hTdCd2RHdJWDtCZdOwWy/G+4dx3hEed0x6SoopOYdt5bq3lW+Ol0mbRzr1QJnuvt8FYjIfL8cIBqidkTpDjyh6V88yg1DNHDOBBqUz8IqOJ//vY0bmQMJp9gb+05UDW7u/Oe4gGIODQlswv534KF2DcaXW9OB7JQyl6f5+O8W6+zBYZ6DAL+J2vtf3CWKSZFomTwu65vrVaLRmTXIIBjQmZEUxWVeC4xN+4Cj5ORvO8GwzoePGDvqwKzrKoupSjqkL5eKqMpCLouOn8n/x5UWtHQS1NlKgMDFhRObzKMqQhS1S4mz84F3L492GFAlie0xRhywnF+FvAkm+ZIRO0UqM4IwvUXdlqTajjmUz2T0+eXKTKTR5UoNRgP51gdUMT5A4ggT5wU9WkRx7CR9KdWJwwcWzv2YrchoHIXBidQSk+f1ZSzqR7krKSOwFTVJUvEenU17qVaHoAf2he0dMgURJ8PM9JxnSr7p2pZeNPu/O5oPmLuOCmEPVRPSahJL7yj9PK5z3q57e5POIp/wXqFoniFdxRmtmpfZBxoKVlADkwRy34h8k6ZmgtqPTQfUUk/+yH2CAoQu+HyOtUnQof8vc1k4zs8nCTrCSjqvFPjU8mHtVHy1RY0qmK9t99ugXyAKaGON3PlseetIC8WCTt84nM5XGD3VQpbv139yhSPhp2Oiz0IiOsr+L9idVKSvfNSkdNq9aUC7963uAQNud8c4GuDmbENvZYvGNIMxxZhYA86n1RMNtGDZJs6/4hZTL18Kz1yCY9zbbSXTxWTmkaHJziHtgrEPoYpUeb85J229PDEX08yHOkj2HXVdnKKmEaHw3VkB4eM3PhGGdrw2CSUejSaqPQFLdhabcB2zdB4lj/AUnZvNaJc23nHHIauHnhhVrxh/KQ1H4YaYKT9ji/69BIfrTgvoGaPZC10pQKinBHEPMXoFrCd1RX1vutnXXcyT2KTBP4GG+Or0j6Sqxtp5WhxR0aJqIKM6LqMHtTooI0QhWbmSqDEBX/wRS70csVeJSrZ4dqRKit+hz8OalHA7At9e+7gSWTfHAwjl5JhtrltyAab/FII4yKQeZWG8j1fSFGHN+EbOrum2uWuVhxkUPy4coMu+yKY4GxlXfvP+yEVK5GrMECRmFBlySetJK3JOoQXiuLirlHUq+0u88QFMdAJ9+fIdU4+FxneqgW7qM7CHRE8jV4pPSWGFbGzxVZ9CWRWaYIw26VsC1qQJe1WmU7Mrp26IxmWHGwHvZ50uB0mjAHFCiln5QAvqTm2/fsY+Puk+Irt3LQbMwGVWPnb4eona2dSha+eMLOiAQkBvbaitsRqqrAVnndP7gHmO+nYZEKNx/740zTRrFBpOelrGdOa0/eV2mPhUQfozGooxoRADmT8fAcDXo0SsXCHzg9tBnmVMvInQ7+8nXfhcF/fEBjvW3gIWOmp2EWutHQ/sl73MieJWnP/n3DMk2HHcatoIZOMUzo4S4uztODHoSiOJDA1hVj7qADvKB37/OX0opnbii9o6W8naFkWG5Ie7+EWQZdo+xeVYpwGOzcNwDRrxbZpV3fTvWyWKToovncZq+TQj7c4Yhz6XDF0ffljN5hTm4ONwYViFNB4gTJlFxFX00wcWfwWah4uJs2Oa8dHPVT+7viagZiPrSDk/gythdY8glGm+F0DWlzQpWbgSI3ZbdiUQ+ox4GtLUtYgGIQFUvRYbuHqH6CXQ3SM6vkbhV/nAn6UDEWKXdJsO0u5q6UpXci7MlWDNLxoQ9dfGjSc28mX+q+4hkyho4u1XSMy9B6IdH304J7fuAQ88tTorT67AiqvqR6qnZ0icV+MMLh95moxFbrvch6sGAmMEixqeujmiZzBqBmNbzZVORiv9qcbe3CQ6X2i+9D8hMpaWj5jI0u+0wk3bRFK4uDn8T1mnD6l4TrJayf3cZI+duhKcabNj71i5w76S8RZSC6RX4ks0x+XIDc5v3223NmGvceYklbuOJtJa0/MBTOcSDKCM2kUXqPV2BlA9Za8WEO2UrdcyP+AXgM20af3thjlZvA494zdZ0mqjrsKp+VS2MVrBBtj+puSuSHJYf6bnA5/yjqQtbGvAp8hfXQURC53J5oD8rb9F7vQRqdfqpe6xd7DVd+wWZS86mWjyZYKXw312t8nM/gxo0pdvZ8F0x9y3xb9UBM2pZtdYvk3hPz6swhuE1N5j2u7nwtXuEDNcGCSfr+IempeFHFRqO8n8ikASEdKcq2XHGJwfc3lVXOQ5K4JlewcC7yQL1uNtL6iNKCtJmjJiH2PMmXrtpmCeTspFNZlwmiICyPWV9B5ce9H/qP1xjndBzFz0rn75SGDnWUhNZI/aYKNVyzkOleS5VSNxBx1hoiFuG8r+6ctYwF7XL94b95tXQ/+0V5dt0H1xVaOZ7QluoDtMSzuUjV4yUoQESa3zCfZwnW+b5SKndX5nx0GYrVxydMkUdfimZpX/fezcMiaAGwG/jgWF0zS+EL4T7gR8I5R3qUNTifKFJKJL1+AL8CgL+SRB1lgHDp2wQ7cqgqcmskAsT60qisL/UZGgmnlgZ8FkNhv0vAMkzIsz7o6cuLo15hZnrsZveIo+mZKY2cMJjJb4ZlJLcE+YcnpiM84OYjypa9lA7kv4XJaDX9oirhsl9IO/ImbFgYpR73y+xSolXYdDKfZjf/8NR7vE8fu+LYXGoZHO/hxousED6y3sCo/ItECYHWYIui+V5SmAoEvVV8FY8fFMYIc+Llc2CoX5HQISfUAtLu+fGNNV0muidXnBdtnJo25UEqxwvoENdI1lGPhlrXY6/h4kIT5djmsxxSG/EgG/4fPnrThgF9/fbG8n/3LweXvQOGjX0F1Ngt5wuMIWRQk5vtLdvv2M+BNwthHZ7xzIU7zqSVvngVPwgcsTr2d5pTVOxauT1K6ffiBF04jVZEcna+NXhJM5EcRHNuT/iOb0ncn1yuKU8JJnztEzMDjO1qCmaBTyWBR7nQS6K+nfstd/AnBWyGeC5Yi3wlvZAVMpc0m7I7McXb+rXiHM0mHoq0Z/2HOki5LP2cBuIkk84tJ3SRZwWnocrz4aTEIOmwftqMATy5Ur0KRxoUSFNMJYyc1iOfjk3H2JjgecWlQdYHcIEjxGDGeo4S9EKTRokMGNUN2nTj3SO2nHoWbx9WhGe6uB3OgDENGL9aNoPnYKXs4WcobctMxQjjBWa/zpCFwP8nr78xIFfy/64ZtsFBrxSrEHxeXiPa2Kpv456aQ9kDQjJt9XrWKe+JBawtpPUYHmWkUb3Gznp3tC2LbowvJlEe/17srb5yi+sUHEF1z/8Uk4eVYcUUXzyq3YEuqumIBIYqO8J3K5Us7tEXyzhHH8TMLNSQxmDi/w5oYccIwNFMM1+xRTsyjHHtB/rHYJjPW/50Xxb0CZF84NqotCcgIMrR4nUiPnAPd8ZvHeB/235gS1NtzBWtfcDmP8khibSQpY3JW+fdY/9W6iGlPyPIwOgH06fJayaT44sPFIm+QGIkPKSAJOFDeJNG8oc6SAqrYSfCffYfOAx3IsjSdnxQy9JAcS0HxjWnEO3rgSh7bNEecO3f4hb3TRNlczdzhfrwgxUZ0rURI3LfMCpGntF+8NrhtB7RT8sEOaa4NM13T7LWjykRQJFYKNZY0siPBP2WJxjBqL0KynlTPhAcfFyiLZbAhe7YC0XmYo8iJQqdzJQwBK9iOoDkg1XuGy7+Kfe0scamvHN2Z85umcPSiPEQRP3zAWcP5kRNDath7DKrBfQtvOJvEHiihE+qiASrCZep+m7jTD261U9vQGAnR4xBY08ChSh8XItWHvDHARN+GP08h9u6nlJ3rpOoVn9y22NNgx7bOe6QIYe9f6iYbbAzLR1/7AP1A4CQwFi39eZI9BZteze5eas+6JR2s1LqH9tncOmWAhXjE8p3hOtplh/tMbrx+pySNX4BKfZva54zccIa+e59NUifTRsq27AwAtcxg2Bk1Tu7B+LT9Yw2K8tRH6XTcGlvqDM4sYjNBqzh3yAga5iro706tg/Qaa50eln8rjISularEHlfaggogjvd+wNLg44Rj8pMr25+xxS0e9KoEGon5SutuhJ/HBGnEj3+4qNxHu27nkAmZIADiF+Jh53osDuA1fsUnRXf2lJABa30KDkG8E/eci+TkESrdfsPMo6yhWoyjtjYdJbGkjtsQCMW5DOSNYDH0FqDiiVU0nBLJ4+A4ep6aWTrv6w/ozuO4educ7x9IBpGmEY30rsXWwiGJbLGyIo+6qz6J5JBKdjNBsDO7RRweDNMp8ospaGNQSa4NKAHTG8BsGqJSP8oebpVqYpgPS1TiBWnYZKQSRJ5NFs+ULpdICekxevVXAH8uh+De9GT7KsJJzg0CFjALDbC0YrbmCigspJAh2455I6/xyWbPXCYMXwBzbioMgWcNhQBJJ6oIoQ7shwf2TP0Z+X/3NoMpWHmGpoV/JZind8lb9lcxoI44uf37+xc03O1R1bNucf0F5ljrgj2sZlGz/591EJen5GZhrT6qSTIcMu+xIyxyA/zzhy0jjkVfkDKfQ8mE9AmVtbbzHAQNy2PhDIeu7ngoFN635tSOJLR2c6pC/m6n50slFbo0oeHbbiGHyxDk7q3zXHWoHzeF1k4iVdHumYg/nwZOuRzms6rvkmwkJv59Z1p05jxA+Y0yHvDeq1WR8PfS/esm3RHfP3fM+zTlj9ZBJfzvn4OL+IIHRQ5l8pGKAeRL58OjeaU5QU98lAKHydOPDGBalsEHyIKD6iy3RZ65qIm956zQd98htZ1Vgkd7LVC7LSnLb9jRbqS1vHN7lR6bQMmXtQBYSA/+ZW2RQqSo7sToVh+Pxl3EVmsgyO8dXPL4biz7XM8eVz7CqHkrQUinnr79HJWC6Uk19cBurOD6PeOqNYy08Og/A0hbHOgN3dKmVRAPf7itK6x0eb5F70T2zVqG12GHVZieXwIcp/vahuFvriHLJtuM04laiRWNXSiL2MPHQ8e9rr8NIlWDm9uev55FI9zZxwFUPBSewawPe5vkqRLfwZCYd5mZoxtBhNBWvY3ZOVD/21dIUlQanG1n6RygbmAwCHnIB4c7EH2CBYEMDToRQuAuIssviIfdaJglwDgHbLWKNUVDOdqeclBNZjfQfVXbVukPk8DfWLqj9pD4xAOzDeVQcdmg2aLvNKgpZsWs4d+6GlKrpS7qEGvoBkIFh/cVY7DMYrt/JXYuF6DpwB+HbfnuDFc2p47SPNhnmt/ez6/DACBPQ+tgpyWYXUsiviGSp72JNTzd8uFJJZNeKUJZw1c0UTjxdwigh5tL/hWhPl48DY937zymSr1xVqC3RV6wSIpuplH+hss/rsRPAp1/TfxvhJuFsoPbW0586y9YzqEHT4FUu6WSRy0gMJLP2sLqiiZXZ6kPicXsW7M55mV3ugbGQjB7YS7EVqsQzvJTiQbOlcPqwoKK7DTqaeCOXd8kH1tNoe7hjx/UNNdLQQ7IhrJIzxqTTgwcXYMCxhoezDsIHReTIymsHPkCurfteTQcbfwoKN5E9zC2hINOPmhAxLvONzaLXQGMqofuTbFshkB4eUj8U4vBCNp+60iCLnibt4rPuyoWKEHWBYa6FfIykxVKuXkfcb64dCdGCWjv7x1XqkbpHxQB80qhipoSo244pyhIsN91ASu1Q7L75LxGXibY3jb0Y4KZ5zIWsH4kVlvPhangohDO1J9gmL9inGr9hy5BHTQiMcktGoUgOIbFJ72381vYpPxn3ngBbp48mVZd0w6xV8RBaqR3l7CxI9vvMAPYPoXBB18ERoZypza8mAlzv2QxIkNGuRzFENh1SXegBfN7eiazZnwnhbyeMghJpnXzfvHACyjkdH3shRYcJ+oMiOSpInGxm/hxFQxHJZA0Ft/lza</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></saml2:EncryptedAssertion></saml2p:Response>"

	test.SPKey = mustParsePrivateKey(`-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDU8wdiaFmPfTyRYuFlVPi866WrH/2JubkHzp89bBQopDaLXYxi
3PTu3O6Q/KaKxMOFBqrInwqpv/omOGZ4ycQ51O9I+Yc7ybVlW94lTo2gpGf+Y/8E
PsVbnZaFutRctJ4dVIp9aQ2TpLiGT0xX1OzBO/JEgq9GzDRf+B+eqSuglwIDAQAB
AoGBAMuy1eN6cgFiCOgBsB3gVDdTKpww87Qk5ivjqEt28SmXO13A1KNVPS6oQ8SJ
CT5Azc6X/BIAoJCURVL+LHdqebogKljhH/3yIel1kH19vr4E2kTM/tYH+qj8afUS
JEmArUzsmmK8ccuNqBcllqdwCZjxL4CHDUmyRudFcHVX9oyhAkEA/OV1OkjM3CLU
N3sqELdMmHq5QZCUihBmk3/N5OvGdqAFGBlEeewlepEVxkh7JnaNXAXrKHRVu/f/
fbCQxH+qrwJBANeQERF97b9Sibp9xgolb749UWNlAdqmEpmlvmS202TdcaaT1msU
4rRLiQN3X9O9mq4LZMSVethrQAdX1whawpkCQQDk1yGf7xZpMJ8F4U5sN+F4rLyM
Rq8Sy8p2OBTwzCUXXK+fYeXjybsUUMr6VMYTRP2fQr/LKJIX+E5ZxvcIyFmDAkEA
yfjNVUNVaIbQTzEbRlRvT6MqR+PTCefC072NF9aJWR93JimspGZMR7viY6IM4lrr
vBkm0F5yXKaYtoiiDMzlOQJADqmEwXl0D72ZG/2KDg8b4QZEmC9i5gidpQwJXUc6
hU+IVQoLxRq0fBib/36K9tcrrO5Ba4iEvDcNY+D8yGbUtA==
-----END RSA PRIVATE KEY-----
`).(*rsa.PrivateKey)
	test.SPCertificate = mustParseCertificate(`-----BEGIN CERTIFICATE-----
MIIB7zCCAVgCCQDFzbKIp7b3MTANBgkqhkiG9w0BAQUFADA8MQswCQYDVQQGEwJV
UzELMAkGA1UECAwCR0ExDDAKBgNVBAoMA2ZvbzESMBAGA1UEAwwJbG9jYWxob3N0
MB4XDTEzMTAwMjAwMDg1MVoXDTE0MTAwMjAwMDg1MVowPDELMAkGA1UEBhMCVVMx
CzAJBgNVBAgMAkdBMQwwCgYDVQQKDANmb28xEjAQBgNVBAMMCWxvY2FsaG9zdDCB
nzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA1PMHYmhZj308kWLhZVT4vOulqx/9
ibm5B86fPWwUKKQ2i12MYtz07tzukPymisTDhQaqyJ8Kqb/6JjhmeMnEOdTvSPmH
O8m1ZVveJU6NoKRn/mP/BD7FW52WhbrUXLSeHVSKfWkNk6S4hk9MV9TswTvyRIKv
Rsw0X/gfnqkroJcCAwEAATANBgkqhkiG9w0BAQUFAAOBgQCMMlIO+GNcGekevKgk
akpMdAqJfs24maGb90DvTLbRZRD7Xvn1MnVBBS9hzlXiFLYOInXACMW5gcoRFfeT
QLSouMM8o57h0uKjfTmuoWHLQLi6hnF+cvCsEFiJZ4AbF+DgmO6TarJ8O05t8zvn
OwJlNCASPZRH/JmF8tX0hoHuAQ==
-----END CERTIFICATE-----
`)
	test.SP = ServiceProvider{
		Key:         test.SPKey,
		Certificate: test.SPCertificate,
		MetadataURL: mustParseURL("https://sp.example.com/saml2/metadata"),
		AcsURL:      mustParseURL("https://sp.example.com/saml2/acs"),
		IDPMetadata: &EntityDescriptor{},
	}

	test.Key = mustParsePrivateKey("-----BEGIN RSA PRIVATE KEY-----\nMIICXgIBAAKBgQDU8wdiaFmPfTyRYuFlVPi866WrH/2JubkHzp89bBQopDaLXYxi\n3PTu3O6Q/KaKxMOFBqrInwqpv/omOGZ4ycQ51O9I+Yc7ybVlW94lTo2gpGf+Y/8E\nPsVbnZaFutRctJ4dVIp9aQ2TpLiGT0xX1OzBO/JEgq9GzDRf+B+eqSuglwIDAQAB\nAoGBAMuy1eN6cgFiCOgBsB3gVDdTKpww87Qk5ivjqEt28SmXO13A1KNVPS6oQ8SJ\nCT5Azc6X/BIAoJCURVL+LHdqebogKljhH/3yIel1kH19vr4E2kTM/tYH+qj8afUS\nJEmArUzsmmK8ccuNqBcllqdwCZjxL4CHDUmyRudFcHVX9oyhAkEA/OV1OkjM3CLU\nN3sqELdMmHq5QZCUihBmk3/N5OvGdqAFGBlEeewlepEVxkh7JnaNXAXrKHRVu/f/\nfbCQxH+qrwJBANeQERF97b9Sibp9xgolb749UWNlAdqmEpmlvmS202TdcaaT1msU\n4rRLiQN3X9O9mq4LZMSVethrQAdX1whawpkCQQDk1yGf7xZpMJ8F4U5sN+F4rLyM\nRq8Sy8p2OBTwzCUXXK+fYeXjybsUUMr6VMYTRP2fQr/LKJIX+E5ZxvcIyFmDAkEA\nyfjNVUNVaIbQTzEbRlRvT6MqR+PTCefC072NF9aJWR93JimspGZMR7viY6IM4lrr\nvBkm0F5yXKaYtoiiDMzlOQJADqmEwXl0D72ZG/2KDg8b4QZEmC9i5gidpQwJXUc6\nhU+IVQoLxRq0fBib/36K9tcrrO5Ba4iEvDcNY+D8yGbUtA==\n-----END RSA PRIVATE KEY-----\n")
	test.Certificate = mustParseCertificate("-----BEGIN CERTIFICATE-----\nMIIB7zCCAVgCCQDFzbKIp7b3MTANBgkqhkiG9w0BAQUFADA8MQswCQYDVQQGEwJV\nUzELMAkGA1UECAwCR0ExDDAKBgNVBAoMA2ZvbzESMBAGA1UEAwwJbG9jYWxob3N0\nMB4XDTEzMTAwMjAwMDg1MVoXDTE0MTAwMjAwMDg1MVowPDELMAkGA1UEBhMCVVMx\nCzAJBgNVBAgMAkdBMQwwCgYDVQQKDANmb28xEjAQBgNVBAMMCWxvY2FsaG9zdDCB\nnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA1PMHYmhZj308kWLhZVT4vOulqx/9\nibm5B86fPWwUKKQ2i12MYtz07tzukPymisTDhQaqyJ8Kqb/6JjhmeMnEOdTvSPmH\nO8m1ZVveJU6NoKRn/mP/BD7FW52WhbrUXLSeHVSKfWkNk6S4hk9MV9TswTvyRIKv\nRsw0X/gfnqkroJcCAwEAATANBgkqhkiG9w0BAQUFAAOBgQCMMlIO+GNcGekevKgk\nakpMdAqJfs24maGb90DvTLbRZRD7Xvn1MnVBBS9hzlXiFLYOInXACMW5gcoRFfeT\nQLSouMM8o57h0uKjfTmuoWHLQLi6hnF+cvCsEFiJZ4AbF+DgmO6TarJ8O05t8zvn\nOwJlNCASPZRH/JmF8tX0hoHuAQ==\n-----END CERTIFICATE-----\n")

	test.IDP = IdentityProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		Logger:      logger.DefaultLogger,
		MetadataURL: mustParseURL("https://idp.example.com/saml/metadata"),
		SSOURL:      mustParseURL("https://idp.example.com/saml/sso"),
		ServiceProviderProvider: &mockServiceProviderProvider{
			GetServiceProviderFunc: func(r *http.Request, serviceProviderID string) (*EntityDescriptor, error) {
				if serviceProviderID == test.SP.MetadataURL.String() {
					return test.SP.Metadata(), nil
				}
				return nil, os.ErrNotExist
			},
		},
		SessionProvider: &mockSessionProvider{
			GetSessionFunc: func(w http.ResponseWriter, r *http.Request, req *IdpAuthnRequest) *Session {
				return nil
			},
		},
	}

	// bind the service provider and the IDP
	test.SP.IDPMetadata = test.IDP.Metadata()
}

type mockSessionProvider struct {
	GetSessionFunc func(w http.ResponseWriter, r *http.Request, req *IdpAuthnRequest) *Session
}

func (msp *mockSessionProvider) GetSession(w http.ResponseWriter, r *http.Request, req *IdpAuthnRequest) *Session {
	return msp.GetSessionFunc(w, r, req)
}

type mockServiceProviderProvider struct {
	GetServiceProviderFunc func(r *http.Request, serviceProviderID string) (*EntityDescriptor, error)
}

func (mspp *mockServiceProviderProvider) GetServiceProvider(r *http.Request, serviceProviderID string) (*EntityDescriptor, error) {
	return mspp.GetServiceProviderFunc(r, serviceProviderID)
}

func (test *IdentityProviderTest) TestCanProduceMetadata(c *C) {
	c.Assert(test.IDP.Metadata(), DeepEquals, &EntityDescriptor{
		ValidUntil:    TimeNow().Add(DefaultValidDuration),
		CacheDuration: DefaultValidDuration,
		EntityID:      "https://idp.example.com/saml/metadata",
		IDPSSODescriptors: []IDPSSODescriptor{
			IDPSSODescriptor{
				SSODescriptor: SSODescriptor{
					RoleDescriptor: RoleDescriptor{
						ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
						KeyDescriptors: []KeyDescriptor{
							{
								Use: "signing",
								KeyInfo: KeyInfo{
									XMLName:     xml.Name{},
									Certificate: "MIIB7zCCAVgCCQDFzbKIp7b3MTANBgkqhkiG9w0BAQUFADA8MQswCQYDVQQGEwJVUzELMAkGA1UECAwCR0ExDDAKBgNVBAoMA2ZvbzESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTEzMTAwMjAwMDg1MVoXDTE0MTAwMjAwMDg1MVowPDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkdBMQwwCgYDVQQKDANmb28xEjAQBgNVBAMMCWxvY2FsaG9zdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA1PMHYmhZj308kWLhZVT4vOulqx/9ibm5B86fPWwUKKQ2i12MYtz07tzukPymisTDhQaqyJ8Kqb/6JjhmeMnEOdTvSPmHO8m1ZVveJU6NoKRn/mP/BD7FW52WhbrUXLSeHVSKfWkNk6S4hk9MV9TswTvyRIKvRsw0X/gfnqkroJcCAwEAATANBgkqhkiG9w0BAQUFAAOBgQCMMlIO+GNcGekevKgkakpMdAqJfs24maGb90DvTLbRZRD7Xvn1MnVBBS9hzlXiFLYOInXACMW5gcoRFfeTQLSouMM8o57h0uKjfTmuoWHLQLi6hnF+cvCsEFiJZ4AbF+DgmO6TarJ8O05t8zvnOwJlNCASPZRH/JmF8tX0hoHuAQ==",
								},
								EncryptionMethods: nil,
							},
							{
								Use: "encryption",
								KeyInfo: KeyInfo{
									XMLName:     xml.Name{},
									Certificate: "MIIB7zCCAVgCCQDFzbKIp7b3MTANBgkqhkiG9w0BAQUFADA8MQswCQYDVQQGEwJVUzELMAkGA1UECAwCR0ExDDAKBgNVBAoMA2ZvbzESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTEzMTAwMjAwMDg1MVoXDTE0MTAwMjAwMDg1MVowPDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkdBMQwwCgYDVQQKDANmb28xEjAQBgNVBAMMCWxvY2FsaG9zdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA1PMHYmhZj308kWLhZVT4vOulqx/9ibm5B86fPWwUKKQ2i12MYtz07tzukPymisTDhQaqyJ8Kqb/6JjhmeMnEOdTvSPmHO8m1ZVveJU6NoKRn/mP/BD7FW52WhbrUXLSeHVSKfWkNk6S4hk9MV9TswTvyRIKvRsw0X/gfnqkroJcCAwEAATANBgkqhkiG9w0BAQUFAAOBgQCMMlIO+GNcGekevKgkakpMdAqJfs24maGb90DvTLbRZRD7Xvn1MnVBBS9hzlXiFLYOInXACMW5gcoRFfeTQLSouMM8o57h0uKjfTmuoWHLQLi6hnF+cvCsEFiJZ4AbF+DgmO6TarJ8O05t8zvnOwJlNCASPZRH/JmF8tX0hoHuAQ==",
								},
								EncryptionMethods: []EncryptionMethod{
									{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes128-cbc"},
									{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes192-cbc"},
									{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes256-cbc"},
									{Algorithm: "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"},
								},
							},
						},
					},
					NameIDFormats: []NameIDFormat{NameIDFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:transient")},
				},
				SingleSignOnServices: []Endpoint{
					Endpoint{
						Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
						Location: "https://idp.example.com/saml/sso",
					},
					Endpoint{
						Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
						Location: "https://idp.example.com/saml/sso",
					},
				},
			},
		},
	})
}

func (test *IdentityProviderTest) TestHTTPCanHandleMetadataRequest(c *C) {
	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "https://idp.example.com/saml/metadata", nil)
	test.IDP.Handler().ServeHTTP(w, r)
	c.Assert(w.Code, Equals, http.StatusOK)
	c.Assert(w.Header().Get("Content-type"), Equals, "application/samlmetadata+xml")
	c.Assert(strings.HasPrefix(string(w.Body.Bytes()), "<EntityDescriptor"), Equals, true)
}

func (test *IdentityProviderTest) TestHTTPCanHandleSSORequest(c *C) {
	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "https://idp.example.com/saml/sso?RelayState=ThisIsTheRelayState&SAMLRequest=lJJBayoxFIX%2FypC9JhnU5wszAz7lgWCLaNtFd5fMbQ1MkmnunVb%2FfUfbUqEgdhs%2BTr5zkmLW8S5s8KVD4mzvm0Cl6FIwEciRCeCRDFuznd2sTD5Upk2Ro42NyGZEmNjFMI%2BBOo9pi%2BnVWbzfrEqxY27JSEntEPfg2waHNnpJ4JtcgiWRLfoLXYBjwDfu6p%2B8JIoiWy5K4eqBUipXIzVRUwXKKtRK53qkJ3qqQVuNPUjU4TIQQ%2BBS5EqPBzofKH2ntBn%2FMervo8jWnyX%2BuVC78FwKkT1gopNKX1JUxSklXTMIfM0gsv8xeeDL%2BPGk7%2FF0Qg0GdnwQ1cW5PDLUwFDID6uquO1Dlot1bJw9%2FPLRmia%2BzRMCYyk4dSiq6205QSDXOxfy3KAq5Pkvqt4DAAD%2F%2Fw%3D%3D", nil)
	test.IDP.Handler().ServeHTTP(w, r)
	c.Assert(w.Code, Equals, http.StatusOK)

	// rejects requests that are invalid
	w = httptest.NewRecorder()
	r, _ = http.NewRequest("GET", "https://idp.example.com/saml/sso?RelayState=ThisIsTheRelayState&SAMLRequest=PEF1dGhuUmVxdWVzdA%3D%3D", nil)
	test.IDP.Handler().ServeHTTP(w, r)
	c.Assert(w.Code, Equals, http.StatusBadRequest)
}

func (test *IdentityProviderTest) TestCanHandleRequestWithNewSession(c *C) {
	test.IDP.SessionProvider = &mockSessionProvider{
		GetSessionFunc: func(w http.ResponseWriter, r *http.Request, req *IdpAuthnRequest) *Session {
			fmt.Fprintf(w, "RelayState: %s\nSAMLRequest: %s",
				req.RelayState, req.RequestBuffer)
			return nil
		},
	}

	w := httptest.NewRecorder()

	requestURL, err := test.SP.MakeRedirectAuthenticationRequest("ThisIsTheRelayState")
	c.Assert(err, IsNil)

	decodedRequest, err := testsaml.ParseRedirectRequest(requestURL)
	c.Assert(err, IsNil)
	c.Assert(string(decodedRequest), Equals, "<samlp:AuthnRequest xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"id-00020406080a0c0e10121416181a1c1e20222426\" Version=\"2.0\" IssueInstant=\"2015-12-01T01:57:09Z\" Destination=\"https://idp.example.com/saml/sso\" AssertionConsumerServiceURL=\"https://sp.example.com/saml2/acs\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"><saml:Issuer Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">https://sp.example.com/saml2/metadata</saml:Issuer><samlp:NameIDPolicy Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:transient\" AllowCreate=\"true\"/></samlp:AuthnRequest>")
	c.Assert(requestURL.Query().Get("RelayState"), Equals, "ThisIsTheRelayState")

	r, _ := http.NewRequest("GET", requestURL.String(), nil)
	test.IDP.ServeSSO(w, r)
	c.Assert(w.Code, Equals, 200)
	c.Assert(string(w.Body.Bytes()), Equals, ""+
		"RelayState: ThisIsTheRelayState\n"+
		"SAMLRequest: <samlp:AuthnRequest xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"id-00020406080a0c0e10121416181a1c1e20222426\" Version=\"2.0\" IssueInstant=\"2015-12-01T01:57:09Z\" Destination=\"https://idp.example.com/saml/sso\" AssertionConsumerServiceURL=\"https://sp.example.com/saml2/acs\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"><saml:Issuer Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">https://sp.example.com/saml2/metadata</saml:Issuer><samlp:NameIDPolicy Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:transient\" AllowCreate=\"true\"/></samlp:AuthnRequest>")
}

func (test *IdentityProviderTest) TestCanHandleRequestWithExistingSession(c *C) {
	test.IDP.SessionProvider = &mockSessionProvider{
		GetSessionFunc: func(w http.ResponseWriter, r *http.Request, req *IdpAuthnRequest) *Session {
			return &Session{
				ID:       "f00df00df00d",
				UserName: "alice",
			}
		},
	}

	w := httptest.NewRecorder()
	requestURL, err := test.SP.MakeRedirectAuthenticationRequest("ThisIsTheRelayState")
	c.Assert(err, IsNil)

	decodedRequest, err := testsaml.ParseRedirectRequest(requestURL)
	c.Assert(err, IsNil)
	c.Assert(string(decodedRequest), Equals, "<samlp:AuthnRequest xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"id-00020406080a0c0e10121416181a1c1e20222426\" Version=\"2.0\" IssueInstant=\"2015-12-01T01:57:09Z\" Destination=\"https://idp.example.com/saml/sso\" AssertionConsumerServiceURL=\"https://sp.example.com/saml2/acs\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"><saml:Issuer Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">https://sp.example.com/saml2/metadata</saml:Issuer><samlp:NameIDPolicy Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:transient\" AllowCreate=\"true\"/></samlp:AuthnRequest>")

	r, _ := http.NewRequest("GET", requestURL.String(), nil)
	test.IDP.ServeSSO(w, r)
	c.Assert(w.Code, Equals, 200)
	c.Assert(string(w.Body.Bytes()), Matches,
		"^<html><form method=\"post\" action=\"https://sp\\.example\\.com/saml2/acs\" id=\"SAMLResponseForm\"><input type=\"hidden\" name=\"SAMLResponse\" value=\".*\" /><input type=\"hidden\" name=\"RelayState\" value=\"ThisIsTheRelayState\" /><input id=\"SAMLSubmitButton\" type=\"submit\" value=\"Continue\" /></form><script>document\\.getElementById\\('SAMLSubmitButton'\\)\\.style\\.visibility='hidden';</script><script>document\\.getElementById\\('SAMLResponseForm'\\)\\.submit\\(\\);</script></html>$")
}

func (test *IdentityProviderTest) TestCanHandlePostRequestWithExistingSession(c *C) {
	test.IDP.SessionProvider = &mockSessionProvider{
		GetSessionFunc: func(w http.ResponseWriter, r *http.Request, req *IdpAuthnRequest) *Session {
			return &Session{
				ID:       "f00df00df00d",
				UserName: "alice",
			}
		},
	}

	w := httptest.NewRecorder()

	authRequest, err := test.SP.MakeAuthenticationRequest(test.SP.GetSSOBindingLocation(HTTPRedirectBinding))
	c.Assert(err, IsNil)
	authRequestBuf, err := xml.Marshal(authRequest)
	c.Assert(err, IsNil)
	q := url.Values{}
	q.Set("SAMLRequest", base64.StdEncoding.EncodeToString(authRequestBuf))
	q.Set("RelayState", "ThisIsTheRelayState")

	r, _ := http.NewRequest("POST", "https://idp.example.com/saml/sso", strings.NewReader(q.Encode()))
	r.Header.Set("Content-type", "application/x-www-form-urlencoded")

	test.IDP.ServeSSO(w, r)
	c.Assert(w.Code, Equals, 200)
	c.Assert(string(w.Body.Bytes()), Matches,
		"^<html><form method=\"post\" action=\"https://sp\\.example\\.com/saml2/acs\" id=\"SAMLResponseForm\"><input type=\"hidden\" name=\"SAMLResponse\" value=\".*\" /><input type=\"hidden\" name=\"RelayState\" value=\"ThisIsTheRelayState\" /><input id=\"SAMLSubmitButton\" type=\"submit\" value=\"Continue\" /></form><script>document\\.getElementById\\('SAMLSubmitButton'\\)\\.style\\.visibility='hidden';</script><script>document\\.getElementById\\('SAMLResponseForm'\\)\\.submit\\(\\);</script></html>$")
}

func (test *IdentityProviderTest) TestRejectsInvalidRequest(c *C) {
	test.IDP.SessionProvider = &mockSessionProvider{
		GetSessionFunc: func(w http.ResponseWriter, r *http.Request, req *IdpAuthnRequest) *Session {
			panic("not reached")
		},
	}

	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "https://idp.example.com/saml/sso?RelayState=ThisIsTheRelayState&SAMLRequest=XXX", nil)
	test.IDP.ServeSSO(w, r)
	c.Assert(w.Code, Equals, http.StatusBadRequest)

	w = httptest.NewRecorder()
	r, _ = http.NewRequest("POST", "https://idp.example.com/saml/sso",
		strings.NewReader("RelayState=ThisIsTheRelayState&SAMLRequest=XXX"))
	r.Header.Set("Content-type", "application/x-www-form-urlencoded")
	test.IDP.ServeSSO(w, r)
	c.Assert(w.Code, Equals, http.StatusBadRequest)
}

func (test *IdentityProviderTest) TestCanParse(c *C) {
	r, _ := http.NewRequest("GET", "https://idp.example.com/saml/sso?RelayState=ThisIsTheRelayState&SAMLRequest=lJJBayoxFIX%2FypC9JhnU5wszAz7lgWCLaNtFd5fMbQ1MkmnunVb%2FfUfbUqEgdhs%2BTr5zkmLW8S5s8KVD4mzvm0Cl6FIwEciRCeCRDFuznd2sTD5Upk2Ro42NyGZEmNjFMI%2BBOo9pi%2BnVWbzfrEqxY27JSEntEPfg2waHNnpJ4JtcgiWRLfoLXYBjwDfu6p%2B8JIoiWy5K4eqBUipXIzVRUwXKKtRK53qkJ3qqQVuNPUjU4TIQQ%2BBS5EqPBzofKH2ntBn%2FMervo8jWnyX%2BuVC78FwKkT1gopNKX1JUxSklXTMIfM0gsv8xeeDL%2BPGk7%2FF0Qg0GdnwQ1cW5PDLUwFDID6uquO1Dlot1bJw9%2FPLRmia%2BzRMCYyk4dSiq6205QSDXOxfy3KAq5Pkvqt4DAAD%2F%2Fw%3D%3D", nil)
	req, err := NewIdpAuthnRequest(&test.IDP, r)
	c.Assert(err, IsNil)
	c.Assert(req.Validate(), IsNil)

	r, _ = http.NewRequest("GET", "https://idp.example.com/saml/sso?RelayState=ThisIsTheRelayState", nil)
	_, err = NewIdpAuthnRequest(&test.IDP, r)
	c.Assert(err, ErrorMatches, "cannot decompress request: unexpected EOF")

	r, _ = http.NewRequest("GET", "https://idp.example.com/saml/sso?RelayState=ThisIsTheRelayState&SAMLRequest=NotValidBase64", nil)
	_, err = NewIdpAuthnRequest(&test.IDP, r)
	c.Assert(err, ErrorMatches, "cannot decode request: illegal base64 data at input byte 12")

	r, _ = http.NewRequest("GET", "https://idp.example.com/saml/sso?RelayState=ThisIsTheRelayState&SAMLRequest=bm90IGZsYXRlIGVuY29kZWQ%3D", nil)
	_, err = NewIdpAuthnRequest(&test.IDP, r)
	c.Assert(err, ErrorMatches, "cannot decompress request: flate: corrupt input before offset 1")

	r, _ = http.NewRequest("FROBNICATE", "https://idp.example.com/saml/sso?RelayState=ThisIsTheRelayState&SAMLRequest=lJJBayoxFIX%2FypC9JhnU5wszAz7lgWCLaNtFd5fMbQ1MkmnunVb%2FfUfbUqEgdhs%2BTr5zkmLW8S5s8KVD4mzvm0Cl6FIwEciRCeCRDFuznd2sTD5Upk2Ro42NyGZEmNjFMI%2BBOo9pi%2BnVWbzfrEqxY27JSEntEPfg2waHNnpJ4JtcgiWRLfoLXYBjwDfu6p%2B8JIoiWy5K4eqBUipXIzVRUwXKKtRK53qkJ3qqQVuNPUjU4TIQQ%2BBS5EqPBzofKH2ntBn%2FMervo8jWnyX%2BuVC78FwKkT1gopNKX1JUxSklXTMIfM0gsv8xeeDL%2BPGk7%2FF0Qg0GdnwQ1cW5PDLUwFDID6uquO1Dlot1bJw9%2FPLRmia%2BzRMCYyk4dSiq6205QSDXOxfy3KAq5Pkvqt4DAAD%2F%2Fw%3D%3D", nil)
	_, err = NewIdpAuthnRequest(&test.IDP, r)
	c.Assert(err, ErrorMatches, "method not allowed")
}

func (test *IdentityProviderTest) TestCanValidate(c *C) {
	req := IdpAuthnRequest{
		Now: TimeNow(),
		IDP: &test.IDP,
		RequestBuffer: []byte("" +
			"<AuthnRequest xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
			"  AssertionConsumerServiceURL=\"https://sp.example.com/saml2/acs\" " +
			"  Destination=\"https://idp.example.com/saml/sso\" " +
			"  ID=\"id-00020406080a0c0e10121416181a1c1e\" " +
			"  IssueInstant=\"2015-12-01T01:57:09Z\" ProtocolBinding=\"\" " +
			"  Version=\"2.0\">" +
			"  <Issuer xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\" " +
			"    Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">https://sp.example.com/saml2/metadata</Issuer>" +
			"  <NameIDPolicy xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
			"    AllowCreate=\"true\">urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDPolicy>" +
			"</AuthnRequest>"),
	}
	c.Assert(req.Validate(), IsNil)
	c.Assert(req.Request, Not(IsNil))
	c.Assert(req.ServiceProviderMetadata, Not(IsNil))
	c.Assert(req.ACSEndpoint, DeepEquals, &IndexedEndpoint{Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", Location: "https://sp.example.com/saml2/acs", Index: 1})

	req = IdpAuthnRequest{
		Now:           TimeNow(),
		IDP:           &test.IDP,
		RequestBuffer: []byte("<AuthnRequest"),
	}
	c.Assert(req.Validate(), ErrorMatches, "XML syntax error on line 1: unexpected EOF")

	req = IdpAuthnRequest{
		Now: TimeNow(),
		IDP: &test.IDP,
		RequestBuffer: []byte("" +
			"<AuthnRequest xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
			"  AssertionConsumerServiceURL=\"https://sp.example.com/saml2/acs\" " +
			"  Destination=\"https://idp.wrongDestination.com/saml/sso\" " +
			"  ID=\"id-00020406080a0c0e10121416181a1c1e\" " +
			"  IssueInstant=\"2015-12-01T01:57:09Z\" ProtocolBinding=\"\" " +
			"  Version=\"2.0\">" +
			"  <Issuer xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\" " +
			"    Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">https://sp.example.com/saml2/metadata</Issuer>" +
			"  <NameIDPolicy xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
			"    AllowCreate=\"true\">urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDPolicy>" +
			"</AuthnRequest>"),
	}
	c.Assert(req.Validate(), ErrorMatches, "expected destination to be \"https://idp.example.com/saml/sso\", not \"https://idp.wrongDestination.com/saml/sso\"")

	req = IdpAuthnRequest{
		Now: TimeNow(),
		IDP: &test.IDP,
		RequestBuffer: []byte("" +
			"<AuthnRequest xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
			"  AssertionConsumerServiceURL=\"https://sp.example.com/saml2/acs\" " +
			"  Destination=\"https://idp.example.com/saml/sso\" " +
			"  ID=\"id-00020406080a0c0e10121416181a1c1e\" " +
			"  IssueInstant=\"2014-12-01T01:57:09Z\" ProtocolBinding=\"\" " +
			"  Version=\"2.0\">" +
			"  <Issuer xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\" " +
			"    Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">https://sp.example.com/saml2/metadata</Issuer>" +
			"  <NameIDPolicy xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
			"    AllowCreate=\"true\">urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDPolicy>" +
			"</AuthnRequest>"),
	}
	c.Assert(req.Validate(), ErrorMatches, "request expired at 2014\\-12\\-01 01:58:39 \\+0000 UTC")

	req = IdpAuthnRequest{
		Now: TimeNow(),
		IDP: &test.IDP,
		RequestBuffer: []byte("" +
			"<AuthnRequest xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
			"  AssertionConsumerServiceURL=\"https://sp.example.com/saml2/acs\" " +
			"  Destination=\"https://idp.example.com/saml/sso\" " +
			"  ID=\"id-00020406080a0c0e10121416181a1c1e\" " +
			"  IssueInstant=\"2015-12-01T01:57:09Z\" ProtocolBinding=\"\" " +
			"  Version=\"4.2\">" +
			"  <Issuer xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\" " +
			"    Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">https://sp.example.com/saml2/metadata</Issuer>" +
			"  <NameIDPolicy xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
			"    AllowCreate=\"true\">urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDPolicy>" +
			"</AuthnRequest>"),
	}
	c.Assert(req.Validate(), ErrorMatches, "expected SAML request version 2.0 got 4.2")

	req = IdpAuthnRequest{
		Now: TimeNow(),
		IDP: &test.IDP,
		RequestBuffer: []byte("" +
			"<AuthnRequest xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
			"  AssertionConsumerServiceURL=\"https://sp.example.com/saml2/acs\" " +
			"  Destination=\"https://idp.example.com/saml/sso\" " +
			"  ID=\"id-00020406080a0c0e10121416181a1c1e\" " +
			"  IssueInstant=\"2015-12-01T01:57:09Z\" ProtocolBinding=\"\" " +
			"  Version=\"2.0\">" +
			"  <Issuer xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\" " +
			"    Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">https://unknownSP.example.com/saml2/metadata</Issuer>" +
			"  <NameIDPolicy xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
			"    AllowCreate=\"true\">urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDPolicy>" +
			"</AuthnRequest>"),
	}
	c.Assert(req.Validate(), ErrorMatches, "cannot handle request from unknown service provider https://unknownSP.example.com/saml2/metadata")

	req = IdpAuthnRequest{
		Now: TimeNow(),
		IDP: &test.IDP,
		RequestBuffer: []byte("" +
			"<AuthnRequest xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
			"  AssertionConsumerServiceURL=\"https://unknown.example.com/saml2/acs\" " +
			"  Destination=\"https://idp.example.com/saml/sso\" " +
			"  ID=\"id-00020406080a0c0e10121416181a1c1e\" " +
			"  IssueInstant=\"2015-12-01T01:57:09Z\" ProtocolBinding=\"\" " +
			"  Version=\"2.0\">" +
			"  <Issuer xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\" " +
			"    Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">https://sp.example.com/saml2/metadata</Issuer>" +
			"  <NameIDPolicy xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
			"    AllowCreate=\"true\">urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDPolicy>" +
			"</AuthnRequest>"),
	}
	c.Assert(req.Validate(), ErrorMatches, "cannot find assertion consumer service: file does not exist")

}

func (test *IdentityProviderTest) TestMakeAssertion(c *C) {
	req := IdpAuthnRequest{
		Now: TimeNow(),
		IDP: &test.IDP,
		RequestBuffer: []byte("" +
			"<AuthnRequest xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
			"  AssertionConsumerServiceURL=\"https://sp.example.com/saml2/acs\" " +
			"  Destination=\"https://idp.example.com/saml/sso\" " +
			"  ID=\"id-00020406080a0c0e10121416181a1c1e\" " +
			"  IssueInstant=\"2015-12-01T01:57:09Z\" ProtocolBinding=\"\" " +
			"  Version=\"2.0\">" +
			"  <Issuer xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\" " +
			"    Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">https://sp.example.com/saml2/metadata</Issuer>" +
			"  <NameIDPolicy xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
			"    AllowCreate=\"true\">urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDPolicy>" +
			"</AuthnRequest>"),
	}
	req.HTTPRequest, _ = http.NewRequest("POST", "http://idp.example.com/saml/sso", nil)

	c.Assert(req.Validate(), IsNil)

	err := DefaultAssertionMaker{}.MakeAssertion(&req, &Session{
		ID:       "f00df00df00d",
		UserName: "alice",
	})
	c.Assert(err, IsNil)

	c.Assert(req.Assertion, DeepEquals, &Assertion{
		ID:           "id-00020406080a0c0e10121416181a1c1e20222426",
		IssueInstant: TimeNow(),
		Version:      "2.0",
		Issuer: Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  "https://idp.example.com/saml/metadata",
		},
		Signature: nil,
		Subject: &Subject{
			NameID: &NameID{Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", NameQualifier: "https://idp.example.com/saml/metadata", SPNameQualifier: "https://sp.example.com/saml2/metadata", Value: ""},
			SubjectConfirmations: []SubjectConfirmation{
				SubjectConfirmation{
					Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
					SubjectConfirmationData: &SubjectConfirmationData{
						Address:      "",
						InResponseTo: "id-00020406080a0c0e10121416181a1c1e",
						NotOnOrAfter: TimeNow().Add(MaxIssueDelay),
						Recipient:    "https://sp.example.com/saml2/acs",
					},
				},
			},
		},
		Conditions: &Conditions{
			NotBefore:    TimeNow(),
			NotOnOrAfter: TimeNow().Add(MaxIssueDelay),
			AudienceRestrictions: []AudienceRestriction{
				AudienceRestriction{
					Audience: Audience{Value: "https://sp.example.com/saml2/metadata"},
				},
			},
		},
		AuthnStatements: []AuthnStatement{
			AuthnStatement{
				AuthnInstant:    time.Time{},
				SessionIndex:    "",
				SubjectLocality: &SubjectLocality{},
				AuthnContext: AuthnContext{
					AuthnContextClassRef: &AuthnContextClassRef{Value: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"},
				},
			},
		},
		AttributeStatements: []AttributeStatement{
			AttributeStatement{
				Attributes: []Attribute{
					{
						FriendlyName: "uid",
						Name:         "urn:oid:0.9.2342.19200300.100.1.1",
						NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
						Values: []AttributeValue{
							{
								Type:  "xs:string",
								Value: "alice",
							},
						},
					},
				},
			},
		},
	})
	err = DefaultAssertionMaker{}.MakeAssertion(&req, &Session{
		ID:             "f00df00df00d",
		CreateTime:     TimeNow(),
		ExpireTime:     TimeNow().Add(time.Hour),
		Index:          "9999",
		NameID:         "ba5eba11",
		Groups:         []string{"Users", "Administrators", "♀"},
		UserName:       "alice",
		UserEmail:      "alice@example.com",
		UserCommonName: "Alice Smith",
		UserSurname:    "Smith",
		UserGivenName:  "Alice",
	})
	c.Assert(err, IsNil)

	c.Assert(req.Assertion.AttributeStatements[0].Attributes, DeepEquals, []Attribute{
		{
			FriendlyName: "uid",
			Name:         "urn:oid:0.9.2342.19200300.100.1.1",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []AttributeValue{
				{
					Type:  "xs:string",
					Value: "alice",
				},
			},
		},
		{
			FriendlyName: "eduPersonPrincipalName",
			Name:         "urn:oid:1.3.6.1.4.1.5923.1.1.1.6",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []AttributeValue{
				{
					Type:  "xs:string",
					Value: "alice@example.com",
				},
			},
		},
		{
			FriendlyName: "sn",
			Name:         "urn:oid:2.5.4.4",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []AttributeValue{
				{
					Type:  "xs:string",
					Value: "Smith",
				},
			},
		},
		{
			FriendlyName: "givenName",
			Name:         "urn:oid:2.5.4.42",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []AttributeValue{
				{
					Type:  "xs:string",
					Value: "Alice",
				},
			},
		},
		{
			FriendlyName: "cn",
			Name:         "urn:oid:2.5.4.3",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []AttributeValue{
				{
					Type:  "xs:string",
					Value: "Alice Smith",
				},
			},
		},
		{
			FriendlyName: "eduPersonAffiliation",
			Name:         "urn:oid:1.3.6.1.4.1.5923.1.1.1.1",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []AttributeValue{
				{
					Type:  "xs:string",
					Value: "Users",
				},
				{
					Type:  "xs:string",
					Value: "Administrators",
				},
				{
					Type:  "xs:string",
					Value: "♀",
				},
			},
		},
	})
}

func (test *IdentityProviderTest) TestMarshalAssertion(c *C) {
	req := IdpAuthnRequest{
		Now: TimeNow(),
		IDP: &test.IDP,
		RequestBuffer: []byte("" +
			"<AuthnRequest xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
			"  AssertionConsumerServiceURL=\"https://sp.example.com/saml2/acs\" " +
			"  Destination=\"https://idp.example.com/saml/sso\" " +
			"  ID=\"id-00020406080a0c0e10121416181a1c1e\" " +
			"  IssueInstant=\"2015-12-01T01:57:09Z\" ProtocolBinding=\"\" " +
			"  Version=\"2.0\">" +
			"  <Issuer xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\" " +
			"    Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">https://sp.example.com/saml2/metadata</Issuer>" +
			"  <NameIDPolicy xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
			"    AllowCreate=\"true\">urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDPolicy>" +
			"</AuthnRequest>"),
	}
	req.HTTPRequest, _ = http.NewRequest("POST", "http://idp.example.com/saml/sso", nil)
	err := req.Validate()
	c.Assert(err, IsNil)
	err = DefaultAssertionMaker{}.MakeAssertion(&req, &Session{
		ID:       "f00df00df00d",
		UserName: "alice",
	})
	c.Assert(err, IsNil)
	err = req.MakeAssertionEl()
	c.Assert(err, IsNil)

	// Compare the plaintext first
	expectedPlaintext := "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"id-00020406080a0c0e10121416181a1c1e20222426\" IssueInstant=\"2015-12-01T01:57:09Z\" Version=\"2.0\"><saml:Issuer Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">https://idp.example.com/saml/metadata</saml:Issuer><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><ds:Reference URI=\"#id-00020406080a0c0e10121416181a1c1e20222426\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><ds:DigestValue>gjE0eLUMVt+kK0rIGYvnzHV/2Ok=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>Jm1rrxo2x7SYTnaS97bCdnVLQGeQuCMTjiSUvwzBkWFR+xcPr+n38dXmv0q0R68tO7L2ELhLtBdLm/dWsxruN23TMGVQyHIPMgJExdnYb7fwqx6es/NAdbDUBTbSdMX0vhIlTsHu5F0bJ0Tg0iAo9uRk9VeBdkaxtPa7+4yl1PQ=</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIB7zCCAVgCCQDFzbKIp7b3MTANBgkqhkiG9w0BAQUFADA8MQswCQYDVQQGEwJVUzELMAkGA1UECAwCR0ExDDAKBgNVBAoMA2ZvbzESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTEzMTAwMjAwMDg1MVoXDTE0MTAwMjAwMDg1MVowPDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkdBMQwwCgYDVQQKDANmb28xEjAQBgNVBAMMCWxvY2FsaG9zdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA1PMHYmhZj308kWLhZVT4vOulqx/9ibm5B86fPWwUKKQ2i12MYtz07tzukPymisTDhQaqyJ8Kqb/6JjhmeMnEOdTvSPmHO8m1ZVveJU6NoKRn/mP/BD7FW52WhbrUXLSeHVSKfWkNk6S4hk9MV9TswTvyRIKvRsw0X/gfnqkroJcCAwEAATANBgkqhkiG9w0BAQUFAAOBgQCMMlIO+GNcGekevKgkakpMdAqJfs24maGb90DvTLbRZRD7Xvn1MnVBBS9hzlXiFLYOInXACMW5gcoRFfeTQLSouMM8o57h0uKjfTmuoWHLQLi6hnF+cvCsEFiJZ4AbF+DgmO6TarJ8O05t8zvnOwJlNCASPZRH/JmF8tX0hoHuAQ==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:transient\" NameQualifier=\"https://idp.example.com/saml/metadata\" SPNameQualifier=\"https://sp.example.com/saml2/metadata\"/><saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><saml:SubjectConfirmationData InResponseTo=\"id-00020406080a0c0e10121416181a1c1e\" NotOnOrAfter=\"2015-12-01T01:58:39Z\" Recipient=\"https://sp.example.com/saml2/acs\"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore=\"2015-12-01T01:57:09Z\" NotOnOrAfter=\"2015-12-01T01:58:39Z\"><saml:AudienceRestriction><saml:Audience>https://sp.example.com/saml2/metadata</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant=\"0001-01-01T00:00:00Z\"><saml:SubjectLocality/><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute FriendlyName=\"uid\" Name=\"urn:oid:0.9.2342.19200300.100.1.1\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\"><saml:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">alice</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>"
	actualPlaintext := ""
	{
		doc := etree.NewDocument()
		doc.SetRoot(req.AssertionEl)
		el := doc.FindElement("//EncryptedAssertion/EncryptedData")
		actualPlaintextBuf, err := xmlenc.Decrypt(test.SPKey, el)
		c.Assert(err, IsNil)
		actualPlaintext = string(actualPlaintextBuf)
	}
	c.Assert(actualPlaintext, Equals, expectedPlaintext)

	doc := etree.NewDocument()
	doc.SetRoot(req.AssertionEl)
	assertionBuffer, err := doc.WriteToBytes()
	c.Assert(err, IsNil)
	c.Assert(string(assertionBuffer), Equals, "<saml:EncryptedAssertion><xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" Id=\"_e285ece1511455780875d64ee2d3d0d0\" Type=\"http://www.w3.org/2001/04/xmlenc#Element\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\" xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"/><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><xenc:EncryptedKey Id=\"_6e4ff95ff662a5eee82abdf44a2d0b75\" xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\" xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"/></xenc:EncryptionMethod><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIB7zCCAVgCCQDFzbKIp7b3MTANBgkqhkiG9w0BAQUFADA8MQswCQYDVQQGEwJVUzELMAkGA1UECAwCR0ExDDAKBgNVBAoMA2ZvbzESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTEzMTAwMjAwMDg1MVoXDTE0MTAwMjAwMDg1MVowPDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkdBMQwwCgYDVQQKDANmb28xEjAQBgNVBAMMCWxvY2FsaG9zdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA1PMHYmhZj308kWLhZVT4vOulqx/9ibm5B86fPWwUKKQ2i12MYtz07tzukPymisTDhQaqyJ8Kqb/6JjhmeMnEOdTvSPmHO8m1ZVveJU6NoKRn/mP/BD7FW52WhbrUXLSeHVSKfWkNk6S4hk9MV9TswTvyRIKvRsw0X/gfnqkroJcCAwEAATANBgkqhkiG9w0BAQUFAAOBgQCMMlIO+GNcGekevKgkakpMdAqJfs24maGb90DvTLbRZRD7Xvn1MnVBBS9hzlXiFLYOInXACMW5gcoRFfeTQLSouMM8o57h0uKjfTmuoWHLQLi6hnF+cvCsEFiJZ4AbF+DgmO6TarJ8O05t8zvnOwJlNCASPZRH/JmF8tX0hoHuAQ==</ds:X509Certificate></ds:X509Data></ds:KeyInfo><xenc:CipherData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"><xenc:CipherValue>R9aHQv2U2ZZSuvRaL4/X8TXpm2/1so2IiOz/+NsAzEKoLAg8Sj87Nj5oMrYY2HF5DPQm/N/3+v6wOU9dX62spTzoSWocVzQU+GdTG2DiIIiAAvQwZo1FyUDKS1Fs5voWzgKvs8G43nj68147T96sXY9SyeUBBdhQtXRsEsmKiAs=</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"><xenc:CipherValue>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</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></saml:EncryptedAssertion>")
}

func (test *IdentityProviderTest) TestMakeResponse(c *C) {
	req := IdpAuthnRequest{
		Now: TimeNow(),
		IDP: &test.IDP,
		RequestBuffer: []byte("" +
			"<AuthnRequest xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
			"  AssertionConsumerServiceURL=\"https://sp.example.com/saml2/acs\" " +
			"  Destination=\"https://idp.example.com/saml/sso\" " +
			"  ID=\"id-00020406080a0c0e10121416181a1c1e\" " +
			"  IssueInstant=\"2015-12-01T01:57:09Z\" ProtocolBinding=\"\" " +
			"  Version=\"2.0\">" +
			"  <Issuer xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\" " +
			"    Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">https://sp.example.com/saml2/metadata</Issuer>" +
			"  <NameIDPolicy xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
			"    AllowCreate=\"true\">urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDPolicy>" +
			"</AuthnRequest>"),
	}
	req.HTTPRequest, _ = http.NewRequest("POST", "http://idp.example.com/saml/sso", nil)
	err := req.Validate()
	c.Assert(err, IsNil)
	err = DefaultAssertionMaker{}.MakeAssertion(&req, &Session{
		ID:       "f00df00df00d",
		UserName: "alice",
	})
	c.Assert(err, IsNil)
	err = req.MakeAssertionEl()
	c.Assert(err, IsNil)

	req.AssertionEl = etree.NewElement("this-is-an-encrypted-assertion")
	err = req.MakeResponse()
	c.Assert(err, IsNil)

	response := Response{}
	err = unmarshalEtreeHack(req.ResponseEl, &response)
	c.Assert(err, IsNil)

	doc := etree.NewDocument()
	doc.SetRoot(req.ResponseEl)
	doc.Indent(2)
	responseStr, _ := doc.WriteToString()
	c.Assert(responseStr, DeepEquals, ""+
		"<samlp:Response xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" ID=\"id-282a2c2e30323436383a3c3e40424446484a4c4e\" InResponseTo=\"id-00020406080a0c0e10121416181a1c1e\" Version=\"2.0\" IssueInstant=\"2015-12-01T01:57:09Z\" Destination=\"https://sp.example.com/saml2/acs\">\n"+
		"  <saml:Issuer Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">https://idp.example.com/saml/metadata</saml:Issuer>\n"+
		"  <ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n"+
		"    <ds:SignedInfo>\n"+
		"      <ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n"+
		"      <ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n"+
		"      <ds:Reference URI=\"#id-282a2c2e30323436383a3c3e40424446484a4c4e\">\n"+
		"        <ds:Transforms>\n"+
		"          <ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\n"+
		"          <ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n"+
		"        </ds:Transforms>\n"+
		"        <ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>\n"+
		"        <ds:DigestValue>fGqTakd3fq3s1utz7xTvzJtQc+E=</ds:DigestValue>\n"+
		"      </ds:Reference>\n"+
		"    </ds:SignedInfo>\n"+
		"    <ds:SignatureValue>yXty6VQCvvF6QAR+vXZtLq2/r8Jt2B9jExD1vVfvWY+S1sKPZbNbaKl69YHYXU8lkhymlVNaMsaezQWDisbNfPe0R0UWysp2rfIXpVDGTdp/YHPj1MIODMPrlgWFfcJjgGxox0tTVzaFyOJFSPhn4G8wEI86WHuePnjRcenfxyk=</ds:SignatureValue>\n"+
		"    <ds:KeyInfo>\n"+
		"      <ds:X509Data>\n"+
		"        <ds:X509Certificate>MIIB7zCCAVgCCQDFzbKIp7b3MTANBgkqhkiG9w0BAQUFADA8MQswCQYDVQQGEwJVUzELMAkGA1UECAwCR0ExDDAKBgNVBAoMA2ZvbzESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTEzMTAwMjAwMDg1MVoXDTE0MTAwMjAwMDg1MVowPDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkdBMQwwCgYDVQQKDANmb28xEjAQBgNVBAMMCWxvY2FsaG9zdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA1PMHYmhZj308kWLhZVT4vOulqx/9ibm5B86fPWwUKKQ2i12MYtz07tzukPymisTDhQaqyJ8Kqb/6JjhmeMnEOdTvSPmHO8m1ZVveJU6NoKRn/mP/BD7FW52WhbrUXLSeHVSKfWkNk6S4hk9MV9TswTvyRIKvRsw0X/gfnqkroJcCAwEAATANBgkqhkiG9w0BAQUFAAOBgQCMMlIO+GNcGekevKgkakpMdAqJfs24maGb90DvTLbRZRD7Xvn1MnVBBS9hzlXiFLYOInXACMW5gcoRFfeTQLSouMM8o57h0uKjfTmuoWHLQLi6hnF+cvCsEFiJZ4AbF+DgmO6TarJ8O05t8zvnOwJlNCASPZRH/JmF8tX0hoHuAQ==</ds:X509Certificate>\n"+
		"      </ds:X509Data>\n"+
		"    </ds:KeyInfo>\n"+
		"  </ds:Signature>\n"+
		"  <samlp:Status>\n"+
		"    <samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/>\n"+
		"  </samlp:Status>\n"+
		"  <this-is-an-encrypted-assertion xmlns=\"http://www.w3.org/XML/1998/namespace\"/>\n"+
		"</samlp:Response>\n")
}

func (test *IdentityProviderTest) TestWriteResponse(c *C) {
	req := IdpAuthnRequest{
		Now:        TimeNow(),
		IDP:        &test.IDP,
		RelayState: "THIS_IS_THE_RELAY_STATE",
		RequestBuffer: []byte("" +
			"<AuthnRequest xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
			"  AssertionConsumerServiceURL=\"https://sp.example.com/saml2/acs\" " +
			"  Destination=\"https://idp.example.com/saml/sso\" " +
			"  ID=\"id-00020406080a0c0e10121416181a1c1e\" " +
			"  IssueInstant=\"2015-12-01T01:57:09Z\" ProtocolBinding=\"\" " +
			"  Version=\"2.0\">" +
			"  <Issuer xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\" " +
			"    Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">https://sp.example.com/saml2/metadata</Issuer>" +
			"  <NameIDPolicy xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
			"    AllowCreate=\"true\">urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDPolicy>" +
			"</AuthnRequest>"),
		ResponseEl: etree.NewElement("THIS_IS_THE_SAML_RESPONSE"),
	}
	req.HTTPRequest, _ = http.NewRequest("POST", "http://idp.example.com/saml/sso", nil)
	err := req.Validate()
	c.Assert(err, IsNil)

	w := httptest.NewRecorder()
	err = req.WriteResponse(w)
	c.Assert(err, IsNil)
	c.Assert(w.Code, Equals, 200)
	c.Assert(string(w.Body.Bytes()), Equals, "<html><form method=\"post\" action=\"https://sp.example.com/saml2/acs\" id=\"SAMLResponseForm\"><input type=\"hidden\" name=\"SAMLResponse\" value=\"PFRISVNfSVNfVEhFX1NBTUxfUkVTUE9OU0UvPg==\" /><input type=\"hidden\" name=\"RelayState\" value=\"THIS_IS_THE_RELAY_STATE\" /><input id=\"SAMLSubmitButton\" type=\"submit\" value=\"Continue\" /></form><script>document.getElementById('SAMLSubmitButton').style.visibility='hidden';</script><script>document.getElementById('SAMLResponseForm').submit();</script></html>")
}

func (test *IdentityProviderTest) TestIDPInitiatedNewSession(c *C) {
	test.IDP.SessionProvider = &mockSessionProvider{
		GetSessionFunc: func(w http.ResponseWriter, r *http.Request, req *IdpAuthnRequest) *Session {
			fmt.Fprintf(w, "RelayState: %s", req.RelayState)
			return nil
		},
	}

	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "https://idp.example.com/services/sp/whoami", nil)
	test.IDP.ServeIDPInitiated(w, r, test.SP.MetadataURL.String(), "ThisIsTheRelayState")
	c.Assert(w.Code, Equals, 200)
	c.Assert(string(w.Body.Bytes()), Equals, "RelayState: ThisIsTheRelayState")
}

func (test *IdentityProviderTest) TestIDPInitiatedExistingSession(c *C) {
	test.IDP.SessionProvider = &mockSessionProvider{
		GetSessionFunc: func(w http.ResponseWriter, r *http.Request, req *IdpAuthnRequest) *Session {
			return &Session{
				ID:       "f00df00df00d",
				UserName: "alice",
			}
		},
	}

	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "https://idp.example.com/services/sp/whoami", nil)
	test.IDP.ServeIDPInitiated(w, r, test.SP.MetadataURL.String(), "ThisIsTheRelayState")
	c.Assert(w.Code, Equals, 200)
	c.Assert(string(w.Body.Bytes()), Matches,
		"^<html><form method=\"post\" action=\"https://sp\\.example\\.com/saml2/acs\" id=\"SAMLResponseForm\"><input type=\"hidden\" name=\"SAMLResponse\" value=\".*\" /><input type=\"hidden\" name=\"RelayState\" value=\"ThisIsTheRelayState\" /><input id=\"SAMLSubmitButton\" type=\"submit\" value=\"Continue\" /></form><script>document\\.getElementById\\('SAMLSubmitButton'\\)\\.style\\.visibility='hidden';</script><script>document\\.getElementById\\('SAMLResponseForm'\\)\\.submit\\(\\);</script></html>$")
}

func (test *IdentityProviderTest) TestIDPInitiatedBadServiceProvider(c *C) {
	test.IDP.SessionProvider = &mockSessionProvider{
		GetSessionFunc: func(w http.ResponseWriter, r *http.Request, req *IdpAuthnRequest) *Session {
			return &Session{
				ID:       "f00df00df00d",
				UserName: "alice",
			}
		},
	}

	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "https://idp.example.com/services/sp/whoami", nil)
	test.IDP.ServeIDPInitiated(w, r, "https://wrong.url/metadata", "ThisIsTheRelayState")
	c.Assert(w.Code, Equals, http.StatusNotFound)
}

func (test *IdentityProviderTest) TestCanHandleUnencryptedResponse(c *C) {
	test.IDP.SessionProvider = &mockSessionProvider{
		GetSessionFunc: func(w http.ResponseWriter, r *http.Request, req *IdpAuthnRequest) *Session {
			return &Session{ID: "f00df00df00d", UserName: "alice"}
		},
	}

	metadata := EntityDescriptor{}
	err := xml.Unmarshal([]byte(`<?xml version='1.0' encoding='UTF-8'?><md:EntityDescriptor ID='_97e2ce01-fa34-4c09-9126-4f7595ef6bf8' entityID='https://gitlab.example.com/users/auth/saml/metadata' xmlns:md='urn:oasis:names:tc:SAML:2.0:metadata' xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion'><md:SPSSODescriptor AuthnRequestsSigned='false' WantAssertionsSigned='false' protocolSupportEnumeration='urn:oasis:names:tc:SAML:2.0:protocol'><md:AssertionConsumerService Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST' Location='https://gitlab.example.com/users/auth/saml/callback' index='0' isDefault='true'/><md:AttributeConsumingService index='1' isDefault='true'><md:ServiceName xml:lang='en'>Required attributes</md:ServiceName><md:RequestedAttribute FriendlyName='Email address' Name='email' NameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:basic'/><md:RequestedAttribute FriendlyName='Full name' Name='name' NameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:basic'/><md:RequestedAttribute FriendlyName='Given name' Name='first_name' NameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:basic'/><md:RequestedAttribute FriendlyName='Family name' Name='last_name' NameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:basic'/></md:AttributeConsumingService></md:SPSSODescriptor></md:EntityDescriptor>`), &metadata)
	c.Assert(err, IsNil)
	test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{
		GetServiceProviderFunc: func(r *http.Request, serviceProviderID string) (*EntityDescriptor, error) {
			if serviceProviderID == "https://gitlab.example.com/users/saml/metadata" {
				return &metadata, nil
			}
			return nil, os.ErrNotExist
		},
	}

	req := IdpAuthnRequest{
		Now: TimeNow(),
		IDP: &test.IDP,
		RequestBuffer: []byte("" +
			"<AuthnRequest xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
			"  AssertionConsumerServiceURL=\"https://gitlab.example.com/users/auth/saml/callback\" " +
			"  Destination=\"https://idp.example.com/saml/sso\" " +
			"  ID=\"id-00020406080a0c0e10121416181a1c1e\" " +
			"  IssueInstant=\"2015-12-01T01:57:09Z\" ProtocolBinding=\"\" " +
			"  Version=\"2.0\">" +
			"  <Issuer xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\" " +
			"    Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">https://gitlab.example.com/users/saml/metadata</Issuer>" +
			"</AuthnRequest>"),
	}
	req.HTTPRequest, _ = http.NewRequest("POST", "http://idp.example.com/saml/sso", nil)
	err = req.Validate()
	c.Assert(err, IsNil)
	err = DefaultAssertionMaker{}.MakeAssertion(&req, &Session{
		ID:       "f00df00df00d",
		UserName: "alice",
	})
	c.Assert(err, IsNil)
	err = req.MakeAssertionEl()
	c.Assert(err, IsNil)

	err = req.MakeResponse()
	c.Assert(err, IsNil)

	doc := etree.NewDocument()
	doc.SetRoot(req.ResponseEl)
	doc.Indent(2)
	responseStr, _ := doc.WriteToString()
	c.Assert(responseStr, DeepEquals, ""+
		"<samlp:Response xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" ID=\"id-282a2c2e30323436383a3c3e40424446484a4c4e\" InResponseTo=\"id-00020406080a0c0e10121416181a1c1e\" Version=\"2.0\" IssueInstant=\"2015-12-01T01:57:09Z\" Destination=\"https://gitlab.example.com/users/auth/saml/callback\">\n"+
		"  <saml:Issuer Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">https://idp.example.com/saml/metadata</saml:Issuer>\n"+
		"  <ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n"+
		"    <ds:SignedInfo>\n"+
		"      <ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n"+
		"      <ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n"+
		"      <ds:Reference URI=\"#id-282a2c2e30323436383a3c3e40424446484a4c4e\">\n"+
		"        <ds:Transforms>\n"+
		"          <ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\n"+
		"          <ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n"+
		"        </ds:Transforms>\n"+
		"        <ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>\n"+
		"        <ds:DigestValue>EJWYGjZq4zltPha+UU/Pcqs+JSc=</ds:DigestValue>\n"+
		"      </ds:Reference>\n"+
		"    </ds:SignedInfo>\n"+
		"    <ds:SignatureValue>C4qEE/hh8tqaM47F6VK9toHJqQxnzzzfwxIc5IUOO1izD/vIFfn4OwKw/SfCFhYj8ZgnVM/BF3oaiWhuAMgFS+MKz2RYnY5h0+DUb1Mv4SjtEPQIv+TL/LGsMJuzPoEkXcxXefz2JCJMXeYM66PfeuBxRpETIe2zIJzZhd9mIrs=</ds:SignatureValue>\n"+
		"    <ds:KeyInfo>\n"+
		"      <ds:X509Data>\n"+
		"        <ds:X509Certificate>MIIB7zCCAVgCCQDFzbKIp7b3MTANBgkqhkiG9w0BAQUFADA8MQswCQYDVQQGEwJVUzELMAkGA1UECAwCR0ExDDAKBgNVBAoMA2ZvbzESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTEzMTAwMjAwMDg1MVoXDTE0MTAwMjAwMDg1MVowPDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkdBMQwwCgYDVQQKDANmb28xEjAQBgNVBAMMCWxvY2FsaG9zdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA1PMHYmhZj308kWLhZVT4vOulqx/9ibm5B86fPWwUKKQ2i12MYtz07tzukPymisTDhQaqyJ8Kqb/6JjhmeMnEOdTvSPmHO8m1ZVveJU6NoKRn/mP/BD7FW52WhbrUXLSeHVSKfWkNk6S4hk9MV9TswTvyRIKvRsw0X/gfnqkroJcCAwEAATANBgkqhkiG9w0BAQUFAAOBgQCMMlIO+GNcGekevKgkakpMdAqJfs24maGb90DvTLbRZRD7Xvn1MnVBBS9hzlXiFLYOInXACMW5gcoRFfeTQLSouMM8o57h0uKjfTmuoWHLQLi6hnF+cvCsEFiJZ4AbF+DgmO6TarJ8O05t8zvnOwJlNCASPZRH/JmF8tX0hoHuAQ==</ds:X509Certificate>\n"+
		"      </ds:X509Data>\n"+
		"    </ds:KeyInfo>\n"+
		"  </ds:Signature>\n"+
		"  <samlp:Status>\n"+
		"    <samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/>\n"+
		"  </samlp:Status>\n"+
		"  <saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"id-00020406080a0c0e10121416181a1c1e20222426\" IssueInstant=\"2015-12-01T01:57:09Z\" Version=\"2.0\">\n"+
		"    <saml:Issuer Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">https://idp.example.com/saml/metadata</saml:Issuer>\n"+
		"    <ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n"+
		"      <ds:SignedInfo>\n"+
		"        <ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n"+
		"        <ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n"+
		"        <ds:Reference URI=\"#id-00020406080a0c0e10121416181a1c1e20222426\">\n"+
		"          <ds:Transforms>\n"+
		"            <ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\n"+
		"            <ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n"+
		"          </ds:Transforms>\n"+
		"          <ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>\n"+
		"          <ds:DigestValue>XPlQkPZr16jJADNHhQ/sma8PBC4=</ds:DigestValue>\n"+
		"        </ds:Reference>\n"+
		"      </ds:SignedInfo>\n"+
		"      <ds:SignatureValue>zDZndnR6twoH0l7j5Qv7hrWxszt+UYSpJ07L0bnN9kD/3jUFkSStok5ubRP5rvOLH6cg4sQX97VuU7EPAmNhj9XcEH7hGMkAAxV/9pbrocSMAm4+HgpyoVl4NSvh9HVWA7tq2WMBgNl6qi05xGws2Fr+zlsax7yr9/hQKdNXL04=</ds:SignatureValue>\n"+
		"      <ds:KeyInfo>\n"+
		"        <ds:X509Data>\n"+
		"          <ds:X509Certificate>MIIB7zCCAVgCCQDFzbKIp7b3MTANBgkqhkiG9w0BAQUFADA8MQswCQYDVQQGEwJVUzELMAkGA1UECAwCR0ExDDAKBgNVBAoMA2ZvbzESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTEzMTAwMjAwMDg1MVoXDTE0MTAwMjAwMDg1MVowPDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkdBMQwwCgYDVQQKDANmb28xEjAQBgNVBAMMCWxvY2FsaG9zdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA1PMHYmhZj308kWLhZVT4vOulqx/9ibm5B86fPWwUKKQ2i12MYtz07tzukPymisTDhQaqyJ8Kqb/6JjhmeMnEOdTvSPmHO8m1ZVveJU6NoKRn/mP/BD7FW52WhbrUXLSeHVSKfWkNk6S4hk9MV9TswTvyRIKvRsw0X/gfnqkroJcCAwEAATANBgkqhkiG9w0BAQUFAAOBgQCMMlIO+GNcGekevKgkakpMdAqJfs24maGb90DvTLbRZRD7Xvn1MnVBBS9hzlXiFLYOInXACMW5gcoRFfeTQLSouMM8o57h0uKjfTmuoWHLQLi6hnF+cvCsEFiJZ4AbF+DgmO6TarJ8O05t8zvnOwJlNCASPZRH/JmF8tX0hoHuAQ==</ds:X509Certificate>\n"+
		"        </ds:X509Data>\n"+
		"      </ds:KeyInfo>\n"+
		"    </ds:Signature>\n"+
		"    <saml:Subject>\n"+
		"      <saml:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:transient\" NameQualifier=\"https://idp.example.com/saml/metadata\" SPNameQualifier=\"https://gitlab.example.com/users/auth/saml/metadata\"/>\n"+
		"      <saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">\n"+
		"        <saml:SubjectConfirmationData InResponseTo=\"id-00020406080a0c0e10121416181a1c1e\" NotOnOrAfter=\"2015-12-01T01:58:39Z\" Recipient=\"https://gitlab.example.com/users/auth/saml/callback\"/>\n"+
		"      </saml:SubjectConfirmation>\n"+
		"    </saml:Subject>\n"+
		"    <saml:Conditions NotBefore=\"2015-12-01T01:57:09Z\" NotOnOrAfter=\"2015-12-01T01:58:39Z\">\n"+
		"      <saml:AudienceRestriction>\n"+
		"        <saml:Audience>https://gitlab.example.com/users/auth/saml/metadata</saml:Audience>\n"+
		"      </saml:AudienceRestriction>\n"+
		"    </saml:Conditions>\n"+
		"    <saml:AuthnStatement AuthnInstant=\"0001-01-01T00:00:00Z\">\n"+
		"      <saml:SubjectLocality/>\n"+
		"      <saml:AuthnContext>\n"+
		"        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>\n"+
		"      </saml:AuthnContext>\n"+
		"    </saml:AuthnStatement>\n"+
		"    <saml:AttributeStatement>\n"+
		"      <saml:Attribute FriendlyName=\"Email address\" Name=\"email\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\">\n"+
		"        <saml:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\"></saml:AttributeValue>\n"+
		"      </saml:Attribute>\n"+
		"      <saml:Attribute FriendlyName=\"Full name\" Name=\"name\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\">\n"+
		"        <saml:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\"></saml:AttributeValue>\n"+
		"      </saml:Attribute>\n"+
		"      <saml:Attribute FriendlyName=\"Given name\" Name=\"first_name\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\">\n"+
		"        <saml:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\"></saml:AttributeValue>\n"+
		"      </saml:Attribute>\n"+
		"      <saml:Attribute FriendlyName=\"Family name\" Name=\"last_name\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\">\n"+
		"        <saml:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\"></saml:AttributeValue>\n"+
		"      </saml:Attribute>\n"+
		"      <saml:Attribute FriendlyName=\"uid\" Name=\"urn:oid:0.9.2342.19200300.100.1.1\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\">\n"+
		"        <saml:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">alice</saml:AttributeValue>\n"+
		"      </saml:Attribute>\n"+
		"    </saml:AttributeStatement>\n"+
		"  </saml:Assertion>\n"+
		"</samlp:Response>\n")
}

func (test *IdentityProviderTest) TestRequestedAttributes(c *C) {
	metadata := EntityDescriptor{}
	err := xml.Unmarshal([]byte(`<?xml version='1.0' encoding='UTF-8'?><md:EntityDescriptor ID='_85fdc505-39e4-4c20-a67f-ca15f4e4064a' entityID='https://dev.aa.kndr.org/users/auth/saml/metadata' xmlns:md='urn:oasis:names:tc:SAML:2.0:metadata' xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion'><md:SPSSODescriptor AuthnRequestsSigned='false' WantAssertionsSigned='false' protocolSupportEnumeration='urn:oasis:names:tc:SAML:2.0:protocol'><md:AssertionConsumerService Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST' Location='https://dev.aa.kndr.org/users/auth/saml/callback' index='0' isDefault='true'/><md:AttributeConsumingService index='1' isDefault='true'><md:ServiceName xml:lang='en'>Required attributes</md:ServiceName><md:RequestedAttribute FriendlyName='Email address' Name='email' NameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:basic'/><md:RequestedAttribute FriendlyName='Full name' Name='name' NameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:basic'/><md:RequestedAttribute FriendlyName='Given name' Name='first_name' NameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:basic'/><md:RequestedAttribute FriendlyName='Family name' Name='last_name' NameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:basic'/></md:AttributeConsumingService></md:SPSSODescriptor></md:EntityDescriptor>`), &metadata)
	c.Assert(err, IsNil)

	requestURL, err := test.SP.MakeRedirectAuthenticationRequest("ThisIsTheRelayState")
	c.Assert(err, IsNil)

	r, _ := http.NewRequest("GET", requestURL.String(), nil)
	req, err := NewIdpAuthnRequest(&test.IDP, r)
	req.ServiceProviderMetadata = &metadata
	req.ACSEndpoint = &metadata.SPSSODescriptors[0].AssertionConsumerServices[0]
	req.SPSSODescriptor = &metadata.SPSSODescriptors[0]
	c.Assert(err, IsNil)
	err = DefaultAssertionMaker{}.MakeAssertion(req, &Session{
		ID:             "f00df00df00d",
		UserName:       "alice",
		UserEmail:      "alice@example.com",
		UserGivenName:  "Alice",
		UserSurname:    "Smith",
		UserCommonName: "Alice Smith",
	})
	c.Assert(err, IsNil)

	c.Assert(req.Assertion.AttributeStatements, DeepEquals, []AttributeStatement{AttributeStatement{
		Attributes: []Attribute{
			Attribute{
				FriendlyName: "Email address",
				Name:         "email",
				NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
				Values: []AttributeValue{
					{
						Type:  "xs:string",
						Value: "alice@example.com",
					},
				},
			},
			Attribute{
				FriendlyName: "Full name",
				Name:         "name",
				NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
				Values: []AttributeValue{
					{
						Type:  "xs:string",
						Value: "Alice Smith",
					},
				},
			},
			Attribute{
				FriendlyName: "Given name",
				Name:         "first_name",
				NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
				Values: []AttributeValue{
					{
						Type:  "xs:string",
						Value: "Alice",
					},
				},
			},
			Attribute{
				FriendlyName: "Family name",
				Name:         "last_name",
				NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
				Values: []AttributeValue{
					{
						Type:  "xs:string",
						Value: "Smith",
					},
				},
			},
			Attribute{
				FriendlyName: "uid",
				Name:         "urn:oid:0.9.2342.19200300.100.1.1",
				NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
				Values: []AttributeValue{
					{
						Type:  "xs:string",
						Value: "alice",
					},
				},
			},
			Attribute{
				FriendlyName: "eduPersonPrincipalName",
				Name:         "urn:oid:1.3.6.1.4.1.5923.1.1.1.6",
				NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
				Values: []AttributeValue{
					{
						Type:  "xs:string",
						Value: "alice@example.com",
					},
				},
			},
			Attribute{
				FriendlyName: "sn",
				Name:         "urn:oid:2.5.4.4",
				NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
				Values: []AttributeValue{
					{
						Type:  "xs:string",
						Value: "Smith",
					},
				},
			},
			Attribute{
				FriendlyName: "givenName",
				Name:         "urn:oid:2.5.4.42",
				NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
				Values: []AttributeValue{
					{
						Type:  "xs:string",
						Value: "Alice",
					},
				},
			},
			Attribute{
				FriendlyName: "cn",
				Name:         "urn:oid:2.5.4.3",
				NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
				Values: []AttributeValue{
					{
						Type:  "xs:string",
						Value: "Alice Smith",
					},
				},
			},
		}}})
}

func (test *IdentityProviderTest) TestNoDestination(c *C) {
	test.IDP.SessionProvider = &mockSessionProvider{
		GetSessionFunc: func(w http.ResponseWriter, r *http.Request, req *IdpAuthnRequest) *Session {
			return &Session{ID: "f00df00df00d", UserName: "alice"}
		},
	}

	metadata := EntityDescriptor{}
	err := xml.Unmarshal([]byte(`<?xml version='1.0' encoding='UTF-8'?><md:EntityDescriptor ID='_97e2ce01-fa34-4c09-9126-4f7595ef6bf8' entityID='https://gitlab.example.com/users/auth/saml/metadata' xmlns:md='urn:oasis:names:tc:SAML:2.0:metadata' xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion'><md:SPSSODescriptor AuthnRequestsSigned='false' WantAssertionsSigned='false' protocolSupportEnumeration='urn:oasis:names:tc:SAML:2.0:protocol'><md:AssertionConsumerService Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST' Location='https://gitlab.example.com/users/auth/saml/callback' index='0' isDefault='true'/><md:AttributeConsumingService index='1' isDefault='true'><md:ServiceName xml:lang='en'>Required attributes</md:ServiceName><md:RequestedAttribute FriendlyName='Email address' Name='email' NameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:basic'/><md:RequestedAttribute FriendlyName='Full name' Name='name' NameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:basic'/><md:RequestedAttribute FriendlyName='Given name' Name='first_name' NameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:basic'/><md:RequestedAttribute FriendlyName='Family name' Name='last_name' NameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:basic'/></md:AttributeConsumingService></md:SPSSODescriptor></md:EntityDescriptor>`), &metadata)
	c.Assert(err, IsNil)
	test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{
		GetServiceProviderFunc: func(r *http.Request, serviceProviderID string) (*EntityDescriptor, error) {
			if serviceProviderID == "https://gitlab.example.com/users/saml/metadata" {
				return &metadata, nil
			}
			return nil, os.ErrNotExist
		},
	}

	req := IdpAuthnRequest{
		Now: TimeNow(),
		IDP: &test.IDP,
		RequestBuffer: []byte("" +
			"<AuthnRequest xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
			"  AssertionConsumerServiceURL=\"https://gitlab.example.com/users/auth/saml/callback\" " +
			"  ID=\"id-00020406080a0c0e10121416181a1c1e\" " +
			"  IssueInstant=\"2015-12-01T01:57:09Z\" ProtocolBinding=\"\" " +
			"  Version=\"2.0\">" +
			"  <Issuer xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\" " +
			"    Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">https://gitlab.example.com/users/saml/metadata</Issuer>" +
			"</AuthnRequest>"),
	}
	req.HTTPRequest, _ = http.NewRequest("POST", "http://idp.example.com/saml/sso", nil)
	err = req.Validate()
	c.Assert(err, IsNil)
	err = DefaultAssertionMaker{}.MakeAssertion(&req, &Session{
		ID:       "f00df00df00d",
		UserName: "alice",
	})
	c.Assert(err, IsNil)
	err = req.MakeAssertionEl()
	c.Assert(err, IsNil)

	err = req.MakeResponse()
	c.Assert(err, IsNil)
}
