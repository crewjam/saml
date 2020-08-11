package saml

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/stretchr/testify/assert"

	"github.com/crewjam/saml/testsaml"
)

type ServiceProviderTest struct {
	AuthnRequest string
	SamlResponse string
	Key          *rsa.PrivateKey
	Certificate  *x509.Certificate
	IDPMetadata  string
}

// Helper to decode SAML redirect binding requests
// http://play.golang.org/p/sTlV0pCS2y
//     x1 := "lJJBj9MwEIX%2FSuR7Y4%2FJRisriVS2Qqq0QNUAB27GmbYWiV08E6D%2FHqeA6AnKdfz85nvPbtYzn8Iev8xIXHyfxkCtmFMw0ZInE%2ByEZNiZfv362ehSmXOKHF0cRbEmwsQ%2BhqcYaJ4w9Zi%2Beofv98%2BtODGfyUgJD3UNVVWV4Zji59JHSXYatbSORLHJO32wi8efG344l5wP6OQ%2FlTEdl4HMWw9%2BRLlgaLnHwSd0LPv%2BrSi2m1b4YaWU0qpStXpUVjmFoEBDBTU8ggUHmIVEM24DsQ3cCq3gYQV6peCdAvMCjIaPotj9ivfSh8GHYytE8QETXQlzfNE1V5d0T1X2d0GieBXTZPnv8mWScxyuUoOBPV9E968iJ2Q7WLaN%2FAnWNW%2Byz3azi6N3l%2F980XGM354SWsZWcJpRdPcDc7KBfMZu5C1B18jbL9b9CAAA%2F%2F8%3D"
//     x2, _ := url.QueryUnescape(x1)
//     x3, _ := base64.StdEncoding.DecodeString(x2)
//     x4, _ := ioutil.ReadAll(flate.NewReader(bytes.NewReader(x3)))
//     fmt.Printf("%s\n", x4)

type testRandomReader struct {
	Next byte
}

func (tr *testRandomReader) Read(p []byte) (n int, err error) {
	for i := 0; i < len(p); i++ {
		p[i] = tr.Next
		tr.Next += 2
	}
	return len(p), nil
}

func NewServiceProviderTest() *ServiceProviderTest {
	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05 MST 2006", "Mon Dec 1 01:57:09 UTC 2015")
		return rv
	}
	Clock = dsig.NewFakeClockAt(TimeNow())

	RandReader = &testRandomReader{}

	t := ServiceProviderTest{}
	t.AuthnRequest = `https://idp.testshib.org/idp/profile/SAML2/Redirect/SSO?RelayState=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1cmkiOiIvIn0.eoUmy2fQduAz--6N82xIOmufY1ZZeRi5x--B7m1pNIY&SAMLRequest=lJJBj9MwEIX%2FSuR7Yzt10sZKIpWtkCotsGqB%2B5BMW4vELp4JsP8et4DYE5Tr%2BPnN957dbGY%2B%2Bz1%2BmZE4%2Bz6NnloxR28DkCPrYUKy3NvD5s2jLXJlLzFw6MMosg0RRnbBPwRP84TxgPGr6%2FHD%2FrEVZ%2BYLWSl1WVXaGJP7UwyfcxckwTQWEnoS2TbtdB6uHn9uuOGSczqgs%2FuUh3i6DmTaenQjyitGIfc4uIg9y8Phnch221a4YVFjpVflcqgM1sUajiWsYGk01KujKVRfJyHRjDtPDJ5bUShdLrReLNX7QtmysrrMK6Pqem3MeqFKq5TInn6lfeX84PypFSL7iJFuwKkN0TU303hPc%2FC7L5G9DnEC%2Frv8OkmxjjepRc%2BOn0X3r14nZBiAoZE%2FwbrmbfLZbZ%2FC6Prn%2F3zgcQzfHiICYys4zii6%2B4E5gieXsBv5kqBr5Msf1%2F0IAAD%2F%2Fw%3D%3D`
	t.SamlResponse = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><saml2p:Response xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\" Destination=\"https://15661444.ngrok.io/saml2/acs\" ID=\"_e9b3332eeaf348da6786aed16300aca9\" InResponseTo=\"id-9e61753d64e928af5a7a341a97f420c9\" IssueInstant=\"2015-12-01T01:56:21.375Z\" Version=\"2.0\"><saml2:Issuer xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">https://idp.testshib.org/idp/shibboleth</saml2:Issuer><saml2p:Status><saml2p:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></saml2p:Status><saml2:EncryptedAssertion xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\"><xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" Id=\"_dab0b1dbbc0595ab06473034e3bb798c\" Type=\"http://www.w3.org/2001/04/xmlenc#Element\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\" xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"/><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><xenc:EncryptedKey Id=\"_dd9264352cef16103cdb21fae97fa951\" xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\" xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"/></xenc:EncryptionMethod><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIB7zCCAVgCCQDFzbKIp7b3MTANBgkqhkiG9w0BAQUFADA8MQswCQYDVQQGEwJVUzELMAkGA1UE\nCAwCR0ExDDAKBgNVBAoMA2ZvbzESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTEzMTAwMjAwMDg1MVoX\nDTE0MTAwMjAwMDg1MVowPDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkdBMQwwCgYDVQQKDANmb28x\nEjAQBgNVBAMMCWxvY2FsaG9zdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA1PMHYmhZj308\nkWLhZVT4vOulqx/9ibm5B86fPWwUKKQ2i12MYtz07tzukPymisTDhQaqyJ8Kqb/6JjhmeMnEOdTv\nSPmHO8m1ZVveJU6NoKRn/mP/BD7FW52WhbrUXLSeHVSKfWkNk6S4hk9MV9TswTvyRIKvRsw0X/gf\nnqkroJcCAwEAATANBgkqhkiG9w0BAQUFAAOBgQCMMlIO+GNcGekevKgkakpMdAqJfs24maGb90Dv\nTLbRZRD7Xvn1MnVBBS9hzlXiFLYOInXACMW5gcoRFfeTQLSouMM8o57h0uKjfTmuoWHLQLi6hnF+\ncvCsEFiJZ4AbF+DgmO6TarJ8O05t8zvnOwJlNCASPZRH/JmF8tX0hoHuAQ==</ds:X509Certificate></ds:X509Data></ds:KeyInfo><xenc:CipherData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"><xenc:CipherValue>i/wh2ubXbhTH5W3hwc5VEf4DH1xifeTuxoe64ULopGJ0M0XxBKgDEIfTg59JUMmDYB4L8UStTFfqJk9BRGcMeYWVfckn5gCwLptD9cz26irw+7Ud7MIorA7z68v8rEyzwagKjz8VKvX1afgec0wobVTNN3M1Bn+SOyMhAu+Z4tE=</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"><xenc:CipherValue>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</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></saml2:EncryptedAssertion></saml2p:Response>"
	t.Key = mustParsePrivateKey("-----BEGIN RSA PRIVATE KEY-----\nMIICXgIBAAKBgQDU8wdiaFmPfTyRYuFlVPi866WrH/2JubkHzp89bBQopDaLXYxi\n3PTu3O6Q/KaKxMOFBqrInwqpv/omOGZ4ycQ51O9I+Yc7ybVlW94lTo2gpGf+Y/8E\nPsVbnZaFutRctJ4dVIp9aQ2TpLiGT0xX1OzBO/JEgq9GzDRf+B+eqSuglwIDAQAB\nAoGBAMuy1eN6cgFiCOgBsB3gVDdTKpww87Qk5ivjqEt28SmXO13A1KNVPS6oQ8SJ\nCT5Azc6X/BIAoJCURVL+LHdqebogKljhH/3yIel1kH19vr4E2kTM/tYH+qj8afUS\nJEmArUzsmmK8ccuNqBcllqdwCZjxL4CHDUmyRudFcHVX9oyhAkEA/OV1OkjM3CLU\nN3sqELdMmHq5QZCUihBmk3/N5OvGdqAFGBlEeewlepEVxkh7JnaNXAXrKHRVu/f/\nfbCQxH+qrwJBANeQERF97b9Sibp9xgolb749UWNlAdqmEpmlvmS202TdcaaT1msU\n4rRLiQN3X9O9mq4LZMSVethrQAdX1whawpkCQQDk1yGf7xZpMJ8F4U5sN+F4rLyM\nRq8Sy8p2OBTwzCUXXK+fYeXjybsUUMr6VMYTRP2fQr/LKJIX+E5ZxvcIyFmDAkEA\nyfjNVUNVaIbQTzEbRlRvT6MqR+PTCefC072NF9aJWR93JimspGZMR7viY6IM4lrr\nvBkm0F5yXKaYtoiiDMzlOQJADqmEwXl0D72ZG/2KDg8b4QZEmC9i5gidpQwJXUc6\nhU+IVQoLxRq0fBib/36K9tcrrO5Ba4iEvDcNY+D8yGbUtA==\n-----END RSA PRIVATE KEY-----\n").(*rsa.PrivateKey)
	t.Certificate = mustParseCertificate("-----BEGIN CERTIFICATE-----\nMIIB7zCCAVgCCQDFzbKIp7b3MTANBgkqhkiG9w0BAQUFADA8MQswCQYDVQQGEwJV\nUzELMAkGA1UECAwCR0ExDDAKBgNVBAoMA2ZvbzESMBAGA1UEAwwJbG9jYWxob3N0\nMB4XDTEzMTAwMjAwMDg1MVoXDTE0MTAwMjAwMDg1MVowPDELMAkGA1UEBhMCVVMx\nCzAJBgNVBAgMAkdBMQwwCgYDVQQKDANmb28xEjAQBgNVBAMMCWxvY2FsaG9zdDCB\nnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA1PMHYmhZj308kWLhZVT4vOulqx/9\nibm5B86fPWwUKKQ2i12MYtz07tzukPymisTDhQaqyJ8Kqb/6JjhmeMnEOdTvSPmH\nO8m1ZVveJU6NoKRn/mP/BD7FW52WhbrUXLSeHVSKfWkNk6S4hk9MV9TswTvyRIKv\nRsw0X/gfnqkroJcCAwEAATANBgkqhkiG9w0BAQUFAAOBgQCMMlIO+GNcGekevKgk\nakpMdAqJfs24maGb90DvTLbRZRD7Xvn1MnVBBS9hzlXiFLYOInXACMW5gcoRFfeT\nQLSouMM8o57h0uKjfTmuoWHLQLi6hnF+cvCsEFiJZ4AbF+DgmO6TarJ8O05t8zvn\nOwJlNCASPZRH/JmF8tX0hoHuAQ==\n-----END CERTIFICATE-----\n")
	t.IDPMetadata = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:mdalg=\"urn:oasis:names:tc:SAML:metadata:algsupport\" xmlns:mdui=\"urn:oasis:names:tc:SAML:metadata:ui\" xmlns:shibmd=\"urn:mace:shibboleth:metadata:1.0\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" Name=\"urn:mace:shibboleth:testshib:two\" entityID=\"https://idp.testshib.org/idp/shibboleth\">\n\t<Extensions>\n\t\t<mdalg:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha512\" />\n\t\t<mdalg:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#sha384\" />\n\t\t<mdalg:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\" />\n\t\t<mdalg:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\" />\n\t\t<mdalg:SigningMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512\" />\n\t\t<mdalg:SigningMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha384\" />\n\t\t<mdalg:SigningMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\" />\n\t\t<mdalg:SigningMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\" />\n\t</Extensions>\n\t<IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:1.1:protocol urn:mace:shibboleth:1.0 urn:oasis:names:tc:SAML:2.0:protocol\">\n\t\t<Extensions>\n\t\t\t<shibmd:Scope regexp=\"false\">testshib.org</shibmd:Scope>\n\t\t\t<mdui:UIInfo>\n\t\t\t\t<mdui:DisplayName xml:lang=\"en\">TestShib Test IdP</mdui:DisplayName>\n\t\t\t\t<mdui:Description xml:lang=\"en\">TestShib IdP. Use this as a source of attributes\n                        for your test SP.</mdui:Description>\n\t\t\t\t<mdui:Logo height=\"88\" width=\"253\">https://www.testshib.org/testshibtwo.jpg</mdui:Logo>\n\t\t\t</mdui:UIInfo>\n\t\t</Extensions>\n\t\t<KeyDescriptor>\n\t\t\t<ds:KeyInfo>\n\t\t\t\t<ds:X509Data>\n\t\t\t\t\t<ds:X509Certificate>MIIEDjCCAvagAwIBAgIBADANBgkqhkiG9w0BAQUFADBnMQswCQYDVQQGEwJVUzEV\n                            MBMGA1UECBMMUGVubnN5bHZhbmlhMRMwEQYDVQQHEwpQaXR0c2J1cmdoMREwDwYD\n                            VQQKEwhUZXN0U2hpYjEZMBcGA1UEAxMQaWRwLnRlc3RzaGliLm9yZzAeFw0wNjA4\n                            MzAyMTEyMjVaFw0xNjA4MjcyMTEyMjVaMGcxCzAJBgNVBAYTAlVTMRUwEwYDVQQI\n                            EwxQZW5uc3lsdmFuaWExEzARBgNVBAcTClBpdHRzYnVyZ2gxETAPBgNVBAoTCFRl\n                            c3RTaGliMRkwFwYDVQQDExBpZHAudGVzdHNoaWIub3JnMIIBIjANBgkqhkiG9w0B\n                            AQEFAAOCAQ8AMIIBCgKCAQEArYkCGuTmJp9eAOSGHwRJo1SNatB5ZOKqDM9ysg7C\n                            yVTDClcpu93gSP10nH4gkCZOlnESNgttg0r+MqL8tfJC6ybddEFB3YBo8PZajKSe\n                            3OQ01Ow3yT4I+Wdg1tsTpSge9gEz7SrC07EkYmHuPtd71CHiUaCWDv+xVfUQX0aT\n                            NPFmDixzUjoYzbGDrtAyCqA8f9CN2txIfJnpHE6q6CmKcoLADS4UrNPlhHSzd614\n                            kR/JYiks0K4kbRqCQF0Dv0P5Di+rEfefC6glV8ysC8dB5/9nb0yh/ojRuJGmgMWH\n                            gWk6h0ihjihqiu4jACovUZ7vVOCgSE5Ipn7OIwqd93zp2wIDAQABo4HEMIHBMB0G\n                            A1UdDgQWBBSsBQ869nh83KqZr5jArr4/7b+QazCBkQYDVR0jBIGJMIGGgBSsBQ86\n                            9nh83KqZr5jArr4/7b+Qa6FrpGkwZzELMAkGA1UEBhMCVVMxFTATBgNVBAgTDFBl\n                            bm5zeWx2YW5pYTETMBEGA1UEBxMKUGl0dHNidXJnaDERMA8GA1UEChMIVGVzdFNo\n                            aWIxGTAXBgNVBAMTEGlkcC50ZXN0c2hpYi5vcmeCAQAwDAYDVR0TBAUwAwEB/zAN\n                            BgkqhkiG9w0BAQUFAAOCAQEAjR29PhrCbk8qLN5MFfSVk98t3CT9jHZoYxd8QMRL\n                            I4j7iYQxXiGJTT1FXs1nd4Rha9un+LqTfeMMYqISdDDI6tv8iNpkOAvZZUosVkUo\n                            93pv1T0RPz35hcHHYq2yee59HJOco2bFlcsH8JBXRSRrJ3Q7Eut+z9uo80JdGNJ4\n                            /SJy5UorZ8KazGj16lfJhOBXldgrhppQBb0Nq6HKHguqmwRfJ+WkxemZXzhediAj\n                            Geka8nz8JjwxpUjAiSWYKLtJhGEaTqCYxCCX2Dw+dOTqUzHOZ7WKv4JXPK5G/Uhr\n                            8K/qhmFT2nIQi538n6rVYLeWj8Bbnl+ev0peYzxFyF5sQA==</ds:X509Certificate>\n\t\t\t\t</ds:X509Data>\n\t\t\t</ds:KeyInfo>\n\t\t\t<EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes256-cbc\" />\n\t\t\t<EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes192-cbc\" />\n\t\t\t<EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\" />\n\t\t\t<EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#tripledes-cbc\" />\n\t\t\t<EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\" />\n\t\t\t<EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-1_5\" />\n\t\t</KeyDescriptor>\n\t\t<ArtifactResolutionService Binding=\"urn:oasis:names:tc:SAML:1.0:bindings:SOAP-binding\" Location=\"https://idp.testshib.org:8443/idp/profile/SAML1/SOAP/ArtifactResolution\" index=\"1\" />\n\t\t<ArtifactResolutionService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:SOAP\" Location=\"https://idp.testshib.org:8443/idp/profile/SAML2/SOAP/ArtifactResolution\" index=\"2\" />\n\t\t<NameIDFormat>urn:mace:shibboleth:1.0:nameIdentifier</NameIDFormat>\n\t\t<NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDFormat>\n\t\t<SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://idp.testshib.org/idp/profile/SAML2/POST/SLO\" />\n\t\t<SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://idp.testshib.org/idp/profile/SAML2/Redirect/SLO\" />\n\t\t<SingleSignOnService Binding=\"urn:mace:shibboleth:1.0:profiles:AuthnRequest\" Location=\"https://idp.testshib.org/idp/profile/Shibboleth/SSO\" />\n\t\t<SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://idp.testshib.org/idp/profile/SAML2/POST/SSO\" />\n\t\t<SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://idp.testshib.org/idp/profile/SAML2/Redirect/SSO\" />\n\t\t<SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:SOAP\" Location=\"https://idp.testshib.org/idp/profile/SAML2/SOAP/ECP\" />\n\t</IDPSSODescriptor>\n\t<AttributeAuthorityDescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:1.1:protocol urn:oasis:names:tc:SAML:2.0:protocol\">\n\t\t<KeyDescriptor>\n\t\t\t<ds:KeyInfo>\n\t\t\t\t<ds:X509Data>\n\t\t\t\t\t<ds:X509Certificate>MIIEDjCCAvagAwIBAgIBADANBgkqhkiG9w0BAQUFADBnMQswCQYDVQQGEwJVUzEV\n                            MBMGA1UECBMMUGVubnN5bHZhbmlhMRMwEQYDVQQHEwpQaXR0c2J1cmdoMREwDwYD\n                            VQQKEwhUZXN0U2hpYjEZMBcGA1UEAxMQaWRwLnRlc3RzaGliLm9yZzAeFw0wNjA4\n                            MzAyMTEyMjVaFw0xNjA4MjcyMTEyMjVaMGcxCzAJBgNVBAYTAlVTMRUwEwYDVQQI\n                            EwxQZW5uc3lsdmFuaWExEzARBgNVBAcTClBpdHRzYnVyZ2gxETAPBgNVBAoTCFRl\n                            c3RTaGliMRkwFwYDVQQDExBpZHAudGVzdHNoaWIub3JnMIIBIjANBgkqhkiG9w0B\n                            AQEFAAOCAQ8AMIIBCgKCAQEArYkCGuTmJp9eAOSGHwRJo1SNatB5ZOKqDM9ysg7C\n                            yVTDClcpu93gSP10nH4gkCZOlnESNgttg0r+MqL8tfJC6ybddEFB3YBo8PZajKSe\n                            3OQ01Ow3yT4I+Wdg1tsTpSge9gEz7SrC07EkYmHuPtd71CHiUaCWDv+xVfUQX0aT\n                            NPFmDixzUjoYzbGDrtAyCqA8f9CN2txIfJnpHE6q6CmKcoLADS4UrNPlhHSzd614\n                            kR/JYiks0K4kbRqCQF0Dv0P5Di+rEfefC6glV8ysC8dB5/9nb0yh/ojRuJGmgMWH\n                            gWk6h0ihjihqiu4jACovUZ7vVOCgSE5Ipn7OIwqd93zp2wIDAQABo4HEMIHBMB0G\n                            A1UdDgQWBBSsBQ869nh83KqZr5jArr4/7b+QazCBkQYDVR0jBIGJMIGGgBSsBQ86\n                            9nh83KqZr5jArr4/7b+Qa6FrpGkwZzELMAkGA1UEBhMCVVMxFTATBgNVBAgTDFBl\n                            bm5zeWx2YW5pYTETMBEGA1UEBxMKUGl0dHNidXJnaDERMA8GA1UEChMIVGVzdFNo\n                            aWIxGTAXBgNVBAMTEGlkcC50ZXN0c2hpYi5vcmeCAQAwDAYDVR0TBAUwAwEB/zAN\n                            BgkqhkiG9w0BAQUFAAOCAQEAjR29PhrCbk8qLN5MFfSVk98t3CT9jHZoYxd8QMRL\n                            I4j7iYQxXiGJTT1FXs1nd4Rha9un+LqTfeMMYqISdDDI6tv8iNpkOAvZZUosVkUo\n                            93pv1T0RPz35hcHHYq2yee59HJOco2bFlcsH8JBXRSRrJ3Q7Eut+z9uo80JdGNJ4\n                            /SJy5UorZ8KazGj16lfJhOBXldgrhppQBb0Nq6HKHguqmwRfJ+WkxemZXzhediAj\n                            Geka8nz8JjwxpUjAiSWYKLtJhGEaTqCYxCCX2Dw+dOTqUzHOZ7WKv4JXPK5G/Uhr\n                            8K/qhmFT2nIQi538n6rVYLeWj8Bbnl+ev0peYzxFyF5sQA==</ds:X509Certificate>\n\t\t\t\t</ds:X509Data>\n\t\t\t</ds:KeyInfo>\n\t\t\t<EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes256-cbc\" />\n\t\t\t<EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes192-cbc\" />\n\t\t\t<EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\" />\n\t\t\t<EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#tripledes-cbc\" />\n\t\t\t<EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\" />\n\t\t\t<EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-1_5\" />\n\t\t</KeyDescriptor>\n\t\t<AttributeService Binding=\"urn:oasis:names:tc:SAML:1.0:bindings:SOAP-binding\" Location=\"https://idp.testshib.org:8443/idp/profile/SAML1/SOAP/AttributeQuery\" />\n\t\t<AttributeService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:SOAP\" Location=\"https://idp.testshib.org:8443/idp/profile/SAML2/SOAP/AttributeQuery\" />\n\t\t<NameIDFormat>urn:mace:shibboleth:1.0:nameIdentifier</NameIDFormat>\n\t\t<NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDFormat>\n\t</AttributeAuthorityDescriptor>\n\t<Organization>\n\t\t<OrganizationName xml:lang=\"en\">TestShib Two Identity Provider</OrganizationName>\n\t\t<OrganizationDisplayName xml:lang=\"en\">TestShib Two</OrganizationDisplayName>\n\t\t<OrganizationURL xml:lang=\"en\">http://www.testshib.org/testshib-two/</OrganizationURL>\n\t</Organization>\n\t<ContactPerson contactType=\"technical\">\n\t\t<GivenName>Nate</GivenName>\n\t\t<SurName>Klingenstein</SurName>\n\t\t<EmailAddress>ndk@internet2.edu</EmailAddress>\n\t</ContactPerson>\n</EntityDescriptor>"
	return &t
}

func TestSPCanSetAuthenticationNameIDFormat(t *testing.T) {
	test := NewServiceProviderTest()

	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("https://15661444.ngrok.io/saml2/metadata"),
		AcsURL:      mustParseURL("https://15661444.ngrok.io/saml2/acs"),
	}

	// defaults to "transient"
	req, err := s.MakeAuthenticationRequest("")
	assert.NoError(t, err)
	assert.Equal(t, string(TransientNameIDFormat), *req.NameIDPolicy.Format)

	// explicitly set to "transient"
	s.AuthnNameIDFormat = TransientNameIDFormat
	req, err = s.MakeAuthenticationRequest("")
	assert.NoError(t, err)
	assert.Equal(t, string(TransientNameIDFormat), *req.NameIDPolicy.Format)

	// explicitly set to "unspecified"
	s.AuthnNameIDFormat = UnspecifiedNameIDFormat
	req, err = s.MakeAuthenticationRequest("")
	assert.NoError(t, err)
	assert.Equal(t, "", *req.NameIDPolicy.Format)

	// explicitly set to "emailAddress"
	s.AuthnNameIDFormat = EmailAddressNameIDFormat
	req, err = s.MakeAuthenticationRequest("")
	assert.NoError(t, err)
	assert.Equal(t, string(EmailAddressNameIDFormat), *req.NameIDPolicy.Format)
}

func TestSPCanProduceMetadataWithEncryptionCert(t *testing.T) {
	test := NewServiceProviderTest()
	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("https://example.com/saml2/metadata"),
		AcsURL:      mustParseURL("https://example.com/saml2/acs"),
		SloURL:      mustParseURL("https://example.com/saml2/slo"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal([]byte(test.IDPMetadata), &s.IDPMetadata)
	assert.NoError(t, err)

	spMetadata, err := xml.MarshalIndent(s.Metadata(), "", "  ")
	assert.NoError(t, err)
	assert.Equal(t, ""+
		"<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2015-12-03T01:57:09Z\" entityID=\"https://example.com/saml2/metadata\">\n"+
		"  <SPSSODescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2015-12-03T01:57:09Z\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" AuthnRequestsSigned=\"false\" WantAssertionsSigned=\"true\">\n"+
		"    <KeyDescriptor use=\"encryption\">\n"+
		"      <KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n"+
		"        <X509Data>\n"+
		"          <X509Certificate>MIIB7zCCAVgCCQDFzbKIp7b3MTANBgkqhkiG9w0BAQUFADA8MQswCQYDVQQGEwJVUzELMAkGA1UECAwCR0ExDDAKBgNVBAoMA2ZvbzESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTEzMTAwMjAwMDg1MVoXDTE0MTAwMjAwMDg1MVowPDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkdBMQwwCgYDVQQKDANmb28xEjAQBgNVBAMMCWxvY2FsaG9zdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA1PMHYmhZj308kWLhZVT4vOulqx/9ibm5B86fPWwUKKQ2i12MYtz07tzukPymisTDhQaqyJ8Kqb/6JjhmeMnEOdTvSPmHO8m1ZVveJU6NoKRn/mP/BD7FW52WhbrUXLSeHVSKfWkNk6S4hk9MV9TswTvyRIKvRsw0X/gfnqkroJcCAwEAATANBgkqhkiG9w0BAQUFAAOBgQCMMlIO+GNcGekevKgkakpMdAqJfs24maGb90DvTLbRZRD7Xvn1MnVBBS9hzlXiFLYOInXACMW5gcoRFfeTQLSouMM8o57h0uKjfTmuoWHLQLi6hnF+cvCsEFiJZ4AbF+DgmO6TarJ8O05t8zvnOwJlNCASPZRH/JmF8tX0hoHuAQ==</X509Certificate>\n"+
		"        </X509Data>\n"+
		"      </KeyInfo>\n"+
		"      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\"></EncryptionMethod>\n"+
		"      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes192-cbc\"></EncryptionMethod>\n"+
		"      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes256-cbc\"></EncryptionMethod>\n"+
		"      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\"></EncryptionMethod>\n"+
		"    </KeyDescriptor>\n"+
		"    <SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://example.com/saml2/slo\" ResponseLocation=\"https://example.com/saml2/slo\"></SingleLogoutService>\n"+
		"    <AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://example.com/saml2/acs\" index=\"1\"></AssertionConsumerService>\n"+
		"  </SPSSODescriptor>\n"+
		"</EntityDescriptor>",
		string(spMetadata))
}

func TestSPCanProduceMetadataWithBothCerts(t *testing.T) {
	test := NewServiceProviderTest()
	s := ServiceProvider{
		Key:             test.Key,
		Certificate:     test.Certificate,
		MetadataURL:     mustParseURL("https://example.com/saml2/metadata"),
		AcsURL:          mustParseURL("https://example.com/saml2/acs"),
		SloURL:          mustParseURL("https://example.com/saml2/slo"),
		IDPMetadata:     &EntityDescriptor{},
		SignatureMethod: "not-empty",
	}
	err := xml.Unmarshal([]byte(test.IDPMetadata), &s.IDPMetadata)
	assert.NoError(t, err)

	spMetadata, err := xml.MarshalIndent(s.Metadata(), "", "  ")
	assert.NoError(t, err)
	assert.Equal(t, ""+
		"<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2015-12-03T01:57:09Z\" entityID=\"https://example.com/saml2/metadata\">\n"+
		"  <SPSSODescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2015-12-03T01:57:09Z\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" AuthnRequestsSigned=\"true\" WantAssertionsSigned=\"true\">\n"+
		"    <KeyDescriptor use=\"encryption\">\n"+
		"      <KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n"+
		"        <X509Data>\n"+
		"          <X509Certificate>MIIB7zCCAVgCCQDFzbKIp7b3MTANBgkqhkiG9w0BAQUFADA8MQswCQYDVQQGEwJVUzELMAkGA1UECAwCR0ExDDAKBgNVBAoMA2ZvbzESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTEzMTAwMjAwMDg1MVoXDTE0MTAwMjAwMDg1MVowPDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkdBMQwwCgYDVQQKDANmb28xEjAQBgNVBAMMCWxvY2FsaG9zdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA1PMHYmhZj308kWLhZVT4vOulqx/9ibm5B86fPWwUKKQ2i12MYtz07tzukPymisTDhQaqyJ8Kqb/6JjhmeMnEOdTvSPmHO8m1ZVveJU6NoKRn/mP/BD7FW52WhbrUXLSeHVSKfWkNk6S4hk9MV9TswTvyRIKvRsw0X/gfnqkroJcCAwEAATANBgkqhkiG9w0BAQUFAAOBgQCMMlIO+GNcGekevKgkakpMdAqJfs24maGb90DvTLbRZRD7Xvn1MnVBBS9hzlXiFLYOInXACMW5gcoRFfeTQLSouMM8o57h0uKjfTmuoWHLQLi6hnF+cvCsEFiJZ4AbF+DgmO6TarJ8O05t8zvnOwJlNCASPZRH/JmF8tX0hoHuAQ==</X509Certificate>\n"+
		"        </X509Data>\n"+
		"      </KeyInfo>\n"+
		"      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\"></EncryptionMethod>\n"+
		"      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes192-cbc\"></EncryptionMethod>\n"+
		"      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes256-cbc\"></EncryptionMethod>\n"+
		"      <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\"></EncryptionMethod>\n"+
		"    </KeyDescriptor>\n"+
		"    <KeyDescriptor use=\"signing\">\n"+
		"      <KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n"+
		"        <X509Data>\n"+
		"          <X509Certificate>MIIB7zCCAVgCCQDFzbKIp7b3MTANBgkqhkiG9w0BAQUFADA8MQswCQYDVQQGEwJVUzELMAkGA1UECAwCR0ExDDAKBgNVBAoMA2ZvbzESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTEzMTAwMjAwMDg1MVoXDTE0MTAwMjAwMDg1MVowPDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkdBMQwwCgYDVQQKDANmb28xEjAQBgNVBAMMCWxvY2FsaG9zdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA1PMHYmhZj308kWLhZVT4vOulqx/9ibm5B86fPWwUKKQ2i12MYtz07tzukPymisTDhQaqyJ8Kqb/6JjhmeMnEOdTvSPmHO8m1ZVveJU6NoKRn/mP/BD7FW52WhbrUXLSeHVSKfWkNk6S4hk9MV9TswTvyRIKvRsw0X/gfnqkroJcCAwEAATANBgkqhkiG9w0BAQUFAAOBgQCMMlIO+GNcGekevKgkakpMdAqJfs24maGb90DvTLbRZRD7Xvn1MnVBBS9hzlXiFLYOInXACMW5gcoRFfeTQLSouMM8o57h0uKjfTmuoWHLQLi6hnF+cvCsEFiJZ4AbF+DgmO6TarJ8O05t8zvnOwJlNCASPZRH/JmF8tX0hoHuAQ==</X509Certificate>\n"+
		"        </X509Data>\n"+
		"      </KeyInfo>\n"+
		"    </KeyDescriptor>\n"+
		"    <SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://example.com/saml2/slo\" ResponseLocation=\"https://example.com/saml2/slo\"></SingleLogoutService>\n"+
		"    <AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://example.com/saml2/acs\" index=\"1\"></AssertionConsumerService>\n"+
		"  </SPSSODescriptor>\n"+
		"</EntityDescriptor>",
		string(spMetadata))
}

func TestCanProduceMetadataNoCerts(t *testing.T) {
	test := NewServiceProviderTest()
	s := ServiceProvider{
		MetadataURL: mustParseURL("https://example.com/saml2/metadata"),
		AcsURL:      mustParseURL("https://example.com/saml2/acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal([]byte(test.IDPMetadata), &s.IDPMetadata)
	assert.NoError(t, err)

	spMetadata, err := xml.MarshalIndent(s.Metadata(), "", "  ")
	assert.NoError(t, err)
	assert.Equal(t, ""+
		"<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2015-12-03T01:57:09Z\" entityID=\"https://example.com/saml2/metadata\">\n"+
		"  <SPSSODescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2015-12-03T01:57:09Z\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" AuthnRequestsSigned=\"false\" WantAssertionsSigned=\"true\">\n"+
		"    <SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"\"></SingleLogoutService>\n"+
		"    <AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://example.com/saml2/acs\" index=\"1\"></AssertionConsumerService>\n"+
		"  </SPSSODescriptor>\n"+
		"</EntityDescriptor>",
		string(spMetadata))
}

func TestCanProduceMetadataEntityID(t *testing.T) {
	test := NewServiceProviderTest()
	s := ServiceProvider{
		EntityID:    "spn:11111111-2222-3333-4444-555555555555",
		MetadataURL: mustParseURL("https://example.com/saml2/metadata"),
		AcsURL:      mustParseURL("https://example.com/saml2/acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal([]byte(test.IDPMetadata), &s.IDPMetadata)
	assert.NoError(t, err)

	spMetadata, err := xml.MarshalIndent(s.Metadata(), "", "  ")
	assert.NoError(t, err)
	assert.Equal(t, ""+
		"<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2015-12-03T01:57:09Z\" entityID=\"spn:11111111-2222-3333-4444-555555555555\">\n"+
		"  <SPSSODescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2015-12-03T01:57:09Z\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" AuthnRequestsSigned=\"false\" WantAssertionsSigned=\"true\">\n"+
		"    <SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"\"></SingleLogoutService>\n"+
		"    <AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://example.com/saml2/acs\" index=\"1\"></AssertionConsumerService>\n"+
		"  </SPSSODescriptor>\n"+
		"</EntityDescriptor>",
		string(spMetadata))
}

func TestSPCanProduceRedirectRequest(t *testing.T) {
	test := NewServiceProviderTest()
	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05.999999999 UTC 2006", "Mon Dec 1 01:31:21.123456789 UTC 2015")
		return rv
	}
	Clock = dsig.NewFakeClockAt(TimeNow())
	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("https://15661444.ngrok.io/saml2/metadata"),
		AcsURL:      mustParseURL("https://15661444.ngrok.io/saml2/acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal([]byte(test.IDPMetadata), &s.IDPMetadata)
	assert.NoError(t, err)

	redirectURL, err := s.MakeRedirectAuthenticationRequest("relayState")
	assert.NoError(t, err)

	decodedRequest, err := testsaml.ParseRedirectRequest(redirectURL)
	assert.NoError(t, err)
	assert.Equal(t,
		"idp.testshib.org",
		redirectURL.Host)
	assert.Equal(t,
		"/idp/profile/SAML2/Redirect/SSO",
		redirectURL.Path)
	assert.Equal(t,
		"<samlp:AuthnRequest xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"id-00020406080a0c0e10121416181a1c1e20222426\" Version=\"2.0\" IssueInstant=\"2015-12-01T01:31:21.123Z\" Destination=\"https://idp.testshib.org/idp/profile/SAML2/Redirect/SSO\" AssertionConsumerServiceURL=\"https://15661444.ngrok.io/saml2/acs\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"><saml:Issuer Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">https://15661444.ngrok.io/saml2/metadata</saml:Issuer><samlp:NameIDPolicy Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:transient\" AllowCreate=\"true\"/></samlp:AuthnRequest>",
		string(decodedRequest))
}

func TestSPCanProducePostRequest(t *testing.T) {
	test := NewServiceProviderTest()
	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05 UTC 2006", "Mon Dec 1 01:31:21 UTC 2015")
		return rv
	}
	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("https://15661444.ngrok.io/saml2/metadata"),
		AcsURL:      mustParseURL("https://15661444.ngrok.io/saml2/acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal([]byte(test.IDPMetadata), &s.IDPMetadata)
	assert.NoError(t, err)

	form, err := s.MakePostAuthenticationRequest("relayState")
	assert.NoError(t, err)

	assert.Equal(t, ``+
		`<form method="post" action="https://idp.testshib.org/idp/profile/SAML2/POST/SSO" id="SAMLRequestForm">`+
		`<input type="hidden" name="SAMLRequest" value="PHNhbWxwOkF1dGhuUmVxdWVzdCB4bWxuczpzYW1sPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiB4bWxuczpzYW1scD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIiBJRD0iaWQtMDAwMjA0MDYwODBhMGMwZTEwMTIxNDE2MTgxYTFjMWUyMDIyMjQyNiIgVmVyc2lvbj0iMi4wIiBJc3N1ZUluc3RhbnQ9IjIwMTUtMTItMDFUMDE6MzE6MjFaIiBEZXN0aW5hdGlvbj0iaHR0cHM6Ly9pZHAudGVzdHNoaWIub3JnL2lkcC9wcm9maWxlL1NBTUwyL1BPU1QvU1NPIiBBc3NlcnRpb25Db25zdW1lclNlcnZpY2VVUkw9Imh0dHBzOi8vMTU2NjE0NDQubmdyb2suaW8vc2FtbDIvYWNzIiBQcm90b2NvbEJpbmRpbmc9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpiaW5kaW5nczpIVFRQLVBPU1QiPjxzYW1sOklzc3VlciBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpuYW1laWQtZm9ybWF0OmVudGl0eSI&#43;aHR0cHM6Ly8xNTY2MTQ0NC5uZ3Jvay5pby9zYW1sMi9tZXRhZGF0YTwvc2FtbDpJc3N1ZXI&#43;PHNhbWxwOk5hbWVJRFBvbGljeSBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpuYW1laWQtZm9ybWF0OnRyYW5zaWVudCIgQWxsb3dDcmVhdGU9InRydWUiLz48L3NhbWxwOkF1dGhuUmVxdWVzdD4=" />`+
		`<input type="hidden" name="RelayState" value="relayState" />`+
		`<input id="SAMLSubmitButton" type="submit" value="Submit" /></form>`+
		`<script>document.getElementById('SAMLSubmitButton').style.visibility="hidden";`+
		`document.getElementById('SAMLRequestForm').submit();</script>`,
		string(form))
}

func TestSPCanProduceSignedRequest(t *testing.T) {
	test := NewServiceProviderTest()
	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05.999999999 UTC 2006", "Mon Dec 1 01:31:21.123456789 UTC 2015")
		return rv
	}
	Clock = dsig.NewFakeClockAt(TimeNow())
	s := ServiceProvider{
		Key:             test.Key,
		Certificate:     test.Certificate,
		MetadataURL:     mustParseURL("https://15661444.ngrok.io/saml2/metadata"),
		AcsURL:          mustParseURL("https://15661444.ngrok.io/saml2/acs"),
		IDPMetadata:     &EntityDescriptor{},
		SignatureMethod: dsig.RSASHA1SignatureMethod,
	}
	err := xml.Unmarshal([]byte(test.IDPMetadata), &s.IDPMetadata)
	assert.NoError(t, err)

	redirectURL, err := s.MakeRedirectAuthenticationRequest("relayState")
	assert.NoError(t, err)

	decodedRequest, err := testsaml.ParseRedirectRequest(redirectURL)
	assert.NoError(t, err)
	assert.Equal(t,
		"idp.testshib.org",
		redirectURL.Host)
	assert.Equal(t,
		"/idp/profile/SAML2/Redirect/SSO",
		redirectURL.Path)
	assert.Equal(t,
		"<samlp:AuthnRequest xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"id-00020406080a0c0e10121416181a1c1e20222426\" Version=\"2.0\" IssueInstant=\"2015-12-01T01:31:21.123Z\" Destination=\"https://idp.testshib.org/idp/profile/SAML2/Redirect/SSO\" AssertionConsumerServiceURL=\"https://15661444.ngrok.io/saml2/acs\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"><saml:Issuer Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">https://15661444.ngrok.io/saml2/metadata</saml:Issuer><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><ds:Reference URI=\"#id-00020406080a0c0e10121416181a1c1e20222426\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><ds:DigestValue>XQ5+kdgOf34vpAemZRFalLlzjr0=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>Wtomi/PiWx0bMFlImy5soCrrDbdY4BR2Qb8woGqc8KsVtXAwvl6lfYE2tuoT0YS5ipPLMMsFG8dB1TmLcA+0lnUcqfBiTiiHEwTIo3193RIsoH3STlOmXqBQf9Ax2nRdX+/4HwIYF58lgUzOb+nur+zGL6mYw2xjQBw6YGaX9Cc=</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIB7zCCAVgCCQDFzbKIp7b3MTANBgkqhkiG9w0BAQUFADA8MQswCQYDVQQGEwJVUzELMAkGA1UECAwCR0ExDDAKBgNVBAoMA2ZvbzESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTEzMTAwMjAwMDg1MVoXDTE0MTAwMjAwMDg1MVowPDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkdBMQwwCgYDVQQKDANmb28xEjAQBgNVBAMMCWxvY2FsaG9zdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA1PMHYmhZj308kWLhZVT4vOulqx/9ibm5B86fPWwUKKQ2i12MYtz07tzukPymisTDhQaqyJ8Kqb/6JjhmeMnEOdTvSPmHO8m1ZVveJU6NoKRn/mP/BD7FW52WhbrUXLSeHVSKfWkNk6S4hk9MV9TswTvyRIKvRsw0X/gfnqkroJcCAwEAATANBgkqhkiG9w0BAQUFAAOBgQCMMlIO+GNcGekevKgkakpMdAqJfs24maGb90DvTLbRZRD7Xvn1MnVBBS9hzlXiFLYOInXACMW5gcoRFfeTQLSouMM8o57h0uKjfTmuoWHLQLi6hnF+cvCsEFiJZ4AbF+DgmO6TarJ8O05t8zvnOwJlNCASPZRH/JmF8tX0hoHuAQ==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><samlp:NameIDPolicy Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:transient\" AllowCreate=\"true\"/></samlp:AuthnRequest>",
		string(decodedRequest))
}

func TestSPFailToProduceSignedRequestWithBogusSignatureMethod(t *testing.T) {
	test := NewServiceProviderTest()
	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05.999999999 UTC 2006", "Mon Dec 1 01:31:21.123456789 UTC 2015")
		return rv
	}
	Clock = dsig.NewFakeClockAt(TimeNow())
	s := ServiceProvider{
		Key:             test.Key,
		Certificate:     test.Certificate,
		MetadataURL:     mustParseURL("https://15661444.ngrok.io/saml2/metadata"),
		AcsURL:          mustParseURL("https://15661444.ngrok.io/saml2/acs"),
		IDPMetadata:     &EntityDescriptor{},
		SignatureMethod: "bogus",
	}
	err := xml.Unmarshal([]byte(test.IDPMetadata), &s.IDPMetadata)
	assert.NoError(t, err)

	_, err = s.MakeRedirectAuthenticationRequest("relayState")
	assert.Errorf(t, err, "invalid signing method bogus")
}

func TestSPCanProducePostLogoutRequest(t *testing.T) {
	test := NewServiceProviderTest()
	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05 UTC 2006", "Mon Dec 1 01:31:21 UTC 2015")
		return rv
	}
	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("https://15661444.ngrok.io/saml2/metadata"),
		AcsURL:      mustParseURL("https://15661444.ngrok.io/saml2/acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal([]byte(test.IDPMetadata), &s.IDPMetadata)
	assert.NoError(t, err)

	form, err := s.MakePostLogoutRequest("ros@octolabs.io", "relayState")
	assert.NoError(t, err)

	assert.Equal(t, ``+
		`<form method="post" action="https://idp.testshib.org/idp/profile/SAML2/POST/SLO" id="SAMLRequestForm">`+
		`<input type="hidden" name="SAMLRequest" value="PHNhbWxwOkxvZ291dFJlcXVlc3QgeG1sbnM6c2FtbD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiIgeG1sbnM6c2FtbHA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpwcm90b2NvbCIgSUQ9ImlkLTAwMDIwNDA2MDgwYTBjMGUxMDEyMTQxNjE4MWExYzFlMjAyMjI0MjYiIFZlcnNpb249IjIuMCIgSXNzdWVJbnN0YW50PSIyMDE1LTEyLTAxVDAxOjMxOjIxWiIgRGVzdGluYXRpb249Imh0dHBzOi8vaWRwLnRlc3RzaGliLm9yZy9pZHAvcHJvZmlsZS9TQU1MMi9QT1NUL1NMTyI&#43;PHNhbWw6SXNzdWVyIEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOm5hbWVpZC1mb3JtYXQ6ZW50aXR5Ij5odHRwczovLzE1NjYxNDQ0Lm5ncm9rLmlvL3NhbWwyL21ldGFkYXRhPC9zYW1sOklzc3Vlcj48c2FtbDpOYW1lSUQgTmFtZVF1YWxpZmllcj0iaHR0cHM6Ly9pZHAudGVzdHNoaWIub3JnL2lkcC9zaGliYm9sZXRoIiBTUE5hbWVRdWFsaWZpZXI9Imh0dHBzOi8vMTU2NjE0NDQubmdyb2suaW8vc2FtbDIvbWV0YWRhdGEiIEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOm5hbWVpZC1mb3JtYXQ6dHJhbnNpZW50Ij5yb3NAb2N0b2xhYnMuaW88L3NhbWw6TmFtZUlEPjwvc2FtbHA6TG9nb3V0UmVxdWVzdD4=" />`+
		`<input type="hidden" name="RelayState" value="relayState" />`+
		`<input id="SAMLSubmitButton" type="submit" value="Submit" /></form>`+
		`<script>document.getElementById('SAMLSubmitButton').style.visibility="hidden";`+
		`document.getElementById('SAMLRequestForm').submit();</script>`,
		string(form))
}

func TestSPCanProduceRedirectLogoutRequest(t *testing.T) {
	test := NewServiceProviderTest()
	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05.999999999 UTC 2006", "Mon Dec 1 01:31:21.123456789 UTC 2015")
		return rv
	}
	Clock = dsig.NewFakeClockAt(TimeNow())
	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("https://15661444.ngrok.io/saml2/metadata"),
		AcsURL:      mustParseURL("https://15661444.ngrok.io/saml2/acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal([]byte(test.IDPMetadata), &s.IDPMetadata)
	assert.NoError(t, err)

	redirectURL, err := s.MakeRedirectLogoutRequest("ross@octolabs.io", "relayState")
	assert.NoError(t, err)

	decodedRequest, err := testsaml.ParseRedirectRequest(redirectURL)
	assert.NoError(t, err)
	assert.Equal(t,
		"idp.testshib.org",
		redirectURL.Host)
	assert.Equal(t,
		"/idp/profile/SAML2/Redirect/SLO",
		redirectURL.Path)
	assert.Equal(t,
		"<samlp:LogoutRequest xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"id-00020406080a0c0e10121416181a1c1e20222426\" Version=\"2.0\" IssueInstant=\"2015-12-01T01:31:21.123Z\" Destination=\"https://idp.testshib.org/idp/profile/SAML2/Redirect/SLO\"><saml:Issuer Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">https://15661444.ngrok.io/saml2/metadata</saml:Issuer><saml:NameID NameQualifier=\"https://idp.testshib.org/idp/shibboleth\" SPNameQualifier=\"https://15661444.ngrok.io/saml2/metadata\" Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:transient\">ross@octolabs.io</saml:NameID></samlp:LogoutRequest>",
		string(decodedRequest))
}

func TestSPCanHandleOneloginResponse(t *testing.T) {
	test := NewServiceProviderTest()
	// An actual response from onelogin
	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05 UTC 2006", "Tue Jan 5 17:53:12 UTC 2016")
		return rv
	}
	Clock = dsig.NewFakeClockAt(TimeNow())
	SamlResponse := `PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWw9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIElEPSJwZnhlZDg4YzQzZC02NTA0LWUxZjEtNWFmMC00MGJlN2YyNzlmYzUiIFZlcnNpb249IjIuMCIgSXNzdWVJbnN0YW50PSIyMDE2LTAxLTA1VDE3OjUzOjExWiIgRGVzdGluYXRpb249Imh0dHBzOi8vMjllZTZkMmUubmdyb2suaW8vc2FtbC9hY3MiIEluUmVzcG9uc2VUbz0iaWQtZDQwYzE1YzEwNGI1MjY5MWVjY2YwYTJhNWM4YTE1NTk1YmU3NTQyMyI+PHNhbWw6SXNzdWVyPmh0dHBzOi8vYXBwLm9uZWxvZ2luLmNvbS9zYW1sL21ldGFkYXRhLzUwMzk4Mzwvc2FtbDpJc3N1ZXI+PGRzOlNpZ25hdHVyZSB4bWxuczpkcz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI+PGRzOlNpZ25lZEluZm8+PGRzOkNhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48ZHM6U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI3JzYS1zaGExIi8+PGRzOlJlZmVyZW5jZSBVUkk9IiNwZnhlZDg4YzQzZC02NTA0LWUxZjEtNWFmMC00MGJlN2YyNzlmYzUiPjxkczpUcmFuc2Zvcm1zPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjZW52ZWxvcGVkLXNpZ25hdHVyZSIvPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48L2RzOlRyYW5zZm9ybXM+PGRzOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNzaGExIi8+PGRzOkRpZ2VzdFZhbHVlPlNWQWFRZzh2bW1TUUw2L1lCbVMyeWRLUlA3ST08L2RzOkRpZ2VzdFZhbHVlPjwvZHM6UmVmZXJlbmNlPjwvZHM6U2lnbmVkSW5mbz48ZHM6U2lnbmF0dXJlVmFsdWU+c0JlVFZQMGJab1BSK2JmeUFrVnY2STNDVjdZOFhxbkoycjhmMStXbXIyZ0ZnblJGODVOdnZTUCtyMUJvN250dU9zd080ZkI0Uks0SHlTYnlsZzRiS0hLSDE5WDkxaFZBekpTeXNmbVMvZDV3ZzFDZmlXV3Q1UzJIQTUwOHRoWHVabndHM1h6NktuV0s4a1JkeDFkYytZUldnYUZ5ZDRnTEc5YUJUc1hPWjd2eC83UDRicnpORW00d1A5LzB0dWZ4Rytuc1k2RHB3bkVHQ2psK1ZVS3BnekVxd05OalFxWUZZU0FYRWsrVnQrWDNjMmQwSElyWlF2WW5OaDAyS3h1d1ZCVGhuM01helFOYU54Qy9zeWYza0RRQ1JyWkNZbytZdER1ZHpKVTlwM0EwWVhIVFFjc2RldHNIWlhDTWozbXV2emMwbUVCbHc0TGJjaEttbmJ5Wm1nPT08L2RzOlNpZ25hdHVyZVZhbHVlPjxkczpLZXlJbmZvPjxkczpYNTA5RGF0YT48ZHM6WDUwOUNlcnRpZmljYXRlPk1JSUVDRENDQXZDZ0F3SUJBZ0lVWHVuMDhDc2xMUldTTHFObkRFMU50R0plZmwwd0RRWUpLb1pJaHZjTkFRRUZCUUF3VXpFTE1Ba0dBMVVFQmhNQ1ZWTXhEREFLQmdOVkJBb01BMk4wZFRFVk1CTUdBMVVFQ3d3TVQyNWxURzluYVc0Z1NXUlFNUjh3SFFZRFZRUUREQlpQYm1WTWIyZHBiaUJCWTJOdmRXNTBJRE15TmpFME1CNFhEVEV6TURrek1ERTVNelUwTkZvWERURTRNVEF3TVRFNU16VTBORm93VXpFTE1Ba0dBMVVFQmhNQ1ZWTXhEREFLQmdOVkJBb01BMk4wZFRFVk1CTUdBMVVFQ3d3TVQyNWxURzluYVc0Z1NXUlFNUjh3SFFZRFZRUUREQlpQYm1WTWIyZHBiaUJCWTJOdmRXNTBJRE15TmpFME1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBME9HOFY4bWhvdmtqNHJoR2hqcmJFeFJZYnpLVjJaeGZ2R2ZFR1hHVXZYYzZEcWVqWUVkaFoybUlmQ0RvamhRamswQnl3aWlyQUtNT3QxR051SDdhV0lFNDdEMGV3dEs1eWxFQW03ZVZtb1k0a3hMQ2FXNXdZckMxU3pNbnBlaXRVeHF2c2JuS3ozalVLWUhSZ2dwZnZWajRzaUhEWmVJWmE5YTVyVXZwTW5uYk9vRmlaQ0lFTnBxM1RDMzNpdk9TWmhFTlJUem12bms1R0RvTEh3LzhxQWdRaXlUM0QxeENrU0JiNTRQSGdrUTVScTFvZExNL2hKK0wwanpDVVFINGd4cFdsRUFhYjRLOXM4ZnBCVUJCaDVnbUpDWWk4VWJJbGhxTzhOMm15bnVtMzNCVS92SjNQbmF3VDRZWWtUd1JVeDZZKzNmcG1SQkhxbDRoODNTTWV3SURBUUFCbzRIVE1JSFFNQXdHQTFVZEV3RUIvd1FDTUFBd0hRWURWUjBPQkJZRUZPZkZGakhGajlhNnhwbmdiMTFycmhnTWU5QXJNSUdRQmdOVkhTTUVnWWd3Z1lXQUZPZkZGakhGajlhNnhwbmdiMTFycmhnTWU5QXJvVmVrVlRCVE1Rc3dDUVlEVlFRR0V3SlZVekVNTUFvR0ExVUVDZ3dEWTNSMU1SVXdFd1lEVlFRTERBeFBibVZNYjJkcGJpQkpaRkF4SHpBZEJnTlZCQU1NRms5dVpVeHZaMmx1SUVGalkyOTFiblFnTXpJMk1UU0NGRjdwOVBBckpTMFZraTZqWnd4TlRiUmlYbjVkTUE0R0ExVWREd0VCL3dRRUF3SUhnREFOQmdrcWhraUc5dzBCQVFVRkFBT0NBUUVBTWdsbjROUE1RbjhHeXZxOENUUCtjMmU2Q1V6Y3ZSRUtuVGhqeFQ5V2N2VjFaVlhNQk5QbTRjVHFUMzYxRWRMelk1eVdMVVdYZDRBdkZuY2lxQjNNSFlhMm5xVG1udkxnbWhrV2UraGRGb05lNStJQThBeEduK25xVUlTbXlCZUN4dVVVQWJSTXVvd2lBcndISXB6cEV5UklZZFNaUk5GMGR2Z2lQWXlyL01pUFhJY3pwSDVuTGt2YkxwY0FGK1I4Wmg5bndZMGcxSlZ5YzZBQjZqN1lleHVVUVpwSEg0czBWZHgvbldtcmNGZUxaS0NUeGNhaEh2VTUwZTF5S1g1dGhmVmFKcUk4UVE3eFp4eXUwVFRzaWFYMHV3NTFKUE96UHVBUHBoMHo2eG9TOW9ZeHV6WjF5OXNOSEg2a0g4R0ZudlMyTXF5SGlOejBoMFNxL3E2bit3PT08L2RzOlg1MDlDZXJ0aWZpY2F0ZT48L2RzOlg1MDlEYXRhPjwvZHM6S2V5SW5mbz48L2RzOlNpZ25hdHVyZT48c2FtbHA6U3RhdHVzPjxzYW1scDpTdGF0dXNDb2RlIFZhbHVlPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6c3RhdHVzOlN1Y2Nlc3MiLz48L3NhbWxwOlN0YXR1cz48c2FtbDpBc3NlcnRpb24geG1sbnM6c2FtbD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiIgeG1sbnM6eHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIiB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIiBWZXJzaW9uPSIyLjAiIElEPSJBZDk0NWFlZGEzOGE1MDhmOGZhYzliYzk2MTNkNTk2NDJjMGQyZDhjYiIgSXNzdWVJbnN0YW50PSIyMDE2LTAxLTA1VDE3OjUzOjExWiI+PHNhbWw6SXNzdWVyPmh0dHBzOi8vYXBwLm9uZWxvZ2luLmNvbS9zYW1sL21ldGFkYXRhLzUwMzk4Mzwvc2FtbDpJc3N1ZXI+PHNhbWw6U3ViamVjdD48c2FtbDpOYW1lSUQgRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoxLjE6bmFtZWlkLWZvcm1hdDplbWFpbEFkZHJlc3MiPnJvc3NAa25kci5vcmc8L3NhbWw6TmFtZUlEPjxzYW1sOlN1YmplY3RDb25maXJtYXRpb24gTWV0aG9kPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6Y206YmVhcmVyIj48c2FtbDpTdWJqZWN0Q29uZmlybWF0aW9uRGF0YSBOb3RPbk9yQWZ0ZXI9IjIwMTYtMDEtMDVUMTc6NTY6MTFaIiBSZWNpcGllbnQ9Imh0dHBzOi8vMjllZTZkMmUubmdyb2suaW8vc2FtbC9hY3MiIEluUmVzcG9uc2VUbz0iaWQtZDQwYzE1YzEwNGI1MjY5MWVjY2YwYTJhNWM4YTE1NTk1YmU3NTQyMyIvPjwvc2FtbDpTdWJqZWN0Q29uZmlybWF0aW9uPjwvc2FtbDpTdWJqZWN0PjxzYW1sOkNvbmRpdGlvbnMgTm90QmVmb3JlPSIyMDE2LTAxLTA1VDE3OjUwOjExWiIgTm90T25PckFmdGVyPSIyMDE2LTAxLTA1VDE3OjU2OjExWiI+PHNhbWw6QXVkaWVuY2VSZXN0cmljdGlvbj48c2FtbDpBdWRpZW5jZT5odHRwczovLzI5ZWU2ZDJlLm5ncm9rLmlvL3NhbWwvbWV0YWRhdGE8L3NhbWw6QXVkaWVuY2U+PC9zYW1sOkF1ZGllbmNlUmVzdHJpY3Rpb24+PC9zYW1sOkNvbmRpdGlvbnM+PHNhbWw6QXV0aG5TdGF0ZW1lbnQgQXV0aG5JbnN0YW50PSIyMDE2LTAxLTA1VDE3OjUzOjEwWiIgU2Vzc2lvbk5vdE9uT3JBZnRlcj0iMjAxNi0wMS0wNlQxNzo1MzoxMVoiIFNlc3Npb25JbmRleD0iX2ViZGNiZTgwLTk1ZmYtMDEzMy1kODcxLTM4Y2EzYTY2MmYxYyI+PHNhbWw6QXV0aG5Db250ZXh0PjxzYW1sOkF1dGhuQ29udGV4dENsYXNzUmVmPnVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphYzpjbGFzc2VzOlBhc3N3b3JkUHJvdGVjdGVkVHJhbnNwb3J0PC9zYW1sOkF1dGhuQ29udGV4dENsYXNzUmVmPjwvc2FtbDpBdXRobkNvbnRleHQ+PC9zYW1sOkF1dGhuU3RhdGVtZW50PjxzYW1sOkF0dHJpYnV0ZVN0YXRlbWVudD48c2FtbDpBdHRyaWJ1dGUgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDpiYXNpYyIgTmFtZT0iVXNlci5lbWFpbCI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0cmluZyI+cm9zc0BrbmRyLm9yZzwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OmJhc2ljIiBOYW1lPSJtZW1iZXJPZiI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0cmluZyIvPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6YmFzaWMiIE5hbWU9IlVzZXIuTGFzdE5hbWUiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiIHhzaTp0eXBlPSJ4czpzdHJpbmciPktpbmRlcjwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OmJhc2ljIiBOYW1lPSJQZXJzb25JbW11dGFibGVJRCI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0cmluZyIvPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6YmFzaWMiIE5hbWU9IlVzZXIuRmlyc3ROYW1lIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIiB4c2k6dHlwZT0ieHM6c3RyaW5nIj5Sb3NzPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PC9zYW1sOkF0dHJpYnV0ZVN0YXRlbWVudD48L3NhbWw6QXNzZXJ0aW9uPjwvc2FtbHA6UmVzcG9uc2U+Cgo=`
	test.IDPMetadata = `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://app.onelogin.com/saml/metadata/503983">
  <IDPSSODescriptor xmlns:ds="http://www.w3.org/2000/09/xmldsig#" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>MIIECDCCAvCgAwIBAgIUXun08CslLRWSLqNnDE1NtGJefl0wDQYJKoZIhvcNAQEF
BQAwUzELMAkGA1UEBhMCVVMxDDAKBgNVBAoMA2N0dTEVMBMGA1UECwwMT25lTG9n
aW4gSWRQMR8wHQYDVQQDDBZPbmVMb2dpbiBBY2NvdW50IDMyNjE0MB4XDTEzMDkz
MDE5MzU0NFoXDTE4MTAwMTE5MzU0NFowUzELMAkGA1UEBhMCVVMxDDAKBgNVBAoM
A2N0dTEVMBMGA1UECwwMT25lTG9naW4gSWRQMR8wHQYDVQQDDBZPbmVMb2dpbiBB
Y2NvdW50IDMyNjE0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0OG8
V8mhovkj4rhGhjrbExRYbzKV2ZxfvGfEGXGUvXc6DqejYEdhZ2mIfCDojhQjk0By
wiirAKMOt1GNuH7aWIE47D0ewtK5ylEAm7eVmoY4kxLCaW5wYrC1SzMnpeitUxqv
sbnKz3jUKYHRggpfvVj4siHDZeIZa9a5rUvpMnnbOoFiZCIENpq3TC33ivOSZhEN
RTzmvnk5GDoLHw/8qAgQiyT3D1xCkSBb54PHgkQ5Rq1odLM/hJ+L0jzCUQH4gxpW
lEAab4K9s8fpBUBBh5gmJCYi8UbIlhqO8N2mynum33BU/vJ3PnawT4YYkTwRUx6Y
+3fpmRBHql4h83SMewIDAQABo4HTMIHQMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYE
FOfFFjHFj9a6xpngb11rrhgMe9ArMIGQBgNVHSMEgYgwgYWAFOfFFjHFj9a6xpng
b11rrhgMe9AroVekVTBTMQswCQYDVQQGEwJVUzEMMAoGA1UECgwDY3R1MRUwEwYD
VQQLDAxPbmVMb2dpbiBJZFAxHzAdBgNVBAMMFk9uZUxvZ2luIEFjY291bnQgMzI2
MTSCFF7p9PArJS0Vki6jZwxNTbRiXn5dMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG
9w0BAQUFAAOCAQEAMgln4NPMQn8Gyvq8CTP+c2e6CUzcvREKnThjxT9WcvV1ZVXM
BNPm4cTqT361EdLzY5yWLUWXd4AvFnciqB3MHYa2nqTmnvLgmhkWe+hdFoNe5+IA
8AxGn+nqUISmyBeCxuUUAbRMuowiArwHIpzpEyRIYdSZRNF0dvgiPYyr/MiPXIcz
pH5nLkvbLpcAF+R8Zh9nwY0g1JVyc6AB6j7YexuUQZpHH4s0Vdx/nWmrcFeLZKCT
xcahHvU50e1yKX5thfVaJqI8QQ7xZxyu0TTsiaX0uw51JPOzPuAPph0z6xoS9oYx
uzZ1y9sNHH6kH8GFnvS2MqyHiNz0h0Sq/q6n+w==</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </KeyDescriptor>
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://app.onelogin.com/trust/saml2/http-post/sso/503983"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://app.onelogin.com/trust/saml2/http-post/sso/503983"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://app.onelogin.com/trust/saml2/soap/sso/503983"/>
  </IDPSSODescriptor>
  <ContactPerson contactType="technical">
    <SurName>Support</SurName>
    <EmailAddress>support@onelogin.com</EmailAddress>
  </ContactPerson>
</EntityDescriptor>
`
	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("https://29ee6d2e.ngrok.io/saml/metadata"),
		AcsURL:      mustParseURL("https://29ee6d2e.ngrok.io/saml/acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal([]byte(test.IDPMetadata), &s.IDPMetadata)
	assert.NoError(t, err)

	req := http.Request{PostForm: url.Values{}}
	req.PostForm.Set("SAMLResponse", SamlResponse)
	assertion, err := s.ParseResponse(&req, []string{"id-d40c15c104b52691eccf0a2a5c8a15595be75423"})
	assert.NoError(t, err)

	assert.Equal(t, "ross@kndr.org", assertion.Subject.NameID.Value)
	assert.Equal(t, []Attribute{
		{
			Name:       "User.email",
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			Values: []AttributeValue{
				{
					Type:  "xs:string",
					Value: "ross@kndr.org",
				},
			},
		},
		{
			Name:       "memberOf",
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			Values: []AttributeValue{
				{
					Type:  "xs:string",
					Value: "",
				},
			},
		},
		{
			Name:       "User.LastName",
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			Values: []AttributeValue{
				{
					Type:  "xs:string",
					Value: "Kinder",
				},
			},
		},
		{
			Name:       "PersonImmutableID",
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			Values: []AttributeValue{
				{
					Type:  "xs:string",
					Value: "",
				},
			},
		},
		{
			Name:       "User.FirstName",
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			Values: []AttributeValue{
				{
					Type:  "xs:string",
					Value: "Ross",
				},
			},
		},
	},
		assertion.AttributeStatements[0].Attributes)
}

func TestSPCanHandleOktaSignedResponseEncryptedAssertion(t *testing.T) {
	test := NewServiceProviderTest()
	// An actual response from okta - captured with trivial.go + test.Key/test.Certificate
	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05 UTC 2006", "Tue Mar 3 19:24:28 UTC 2020")
		return rv
	}
	Clock = dsig.NewFakeClockAt(TimeNow())
	SamlResponse := `PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48c2FtbDJwOlJlc3BvbnNlIERlc3RpbmF0aW9uPSJodHRwOi8vbG9jYWxob3N0OjgwMDAvc2FtbC9hY3MiIElEPSJpZDg0OTUyMTk5Njg5MDU3MzYxODk2OTM5MzMzIiBJblJlc3BvbnNlVG89ImlkLWE3MzY0ZDFlNDQzMmFhOTA4NWE3YThiZDgyNGVhMmZhOGZhOGY2ODQiIElzc3VlSW5zdGFudD0iMjAyMC0wMy0wM1QxOToyNDoyOS4yMTNaIiBWZXJzaW9uPSIyLjAiIHhtbG5zOnNhbWwycD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIj48c2FtbDI6SXNzdWVyIEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOm5hbWVpZC1mb3JtYXQ6ZW50aXR5IiB4bWxuczpzYW1sMj0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiI+aHR0cDovL3d3dy5va3RhLmNvbS9leGtwcHNhMXF3dUZWNEQ3ejBoNzwvc2FtbDI6SXNzdWVyPjxkczpTaWduYXR1cmUgeG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPjxkczpTaWduZWRJbmZvPjxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PGRzOlNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZHNpZy1tb3JlI3JzYS1zaGEyNTYiLz48ZHM6UmVmZXJlbmNlIFVSST0iI2lkODQ5NTIxOTk2ODkwNTczNjE4OTY5MzkzMzMiPjxkczpUcmFuc2Zvcm1zPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjZW52ZWxvcGVkLXNpZ25hdHVyZSIvPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48L2RzOlRyYW5zZm9ybXM+PGRzOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jI3NoYTI1NiIvPjxkczpEaWdlc3RWYWx1ZT5mSmFzQXdHNHQrOTh3MGFDY1h1dy9VbEdqQkRRcWtxeWpYQjFIMWdtN09nPTwvZHM6RGlnZXN0VmFsdWU+PC9kczpSZWZlcmVuY2U+PC9kczpTaWduZWRJbmZvPjxkczpTaWduYXR1cmVWYWx1ZT5SR2RFaHJRRURiRHRxcHVrRlFveEtmVTl2cmJxNnNyTjJucHBSOG13bnhDL21VZG1kT0lTMlRwRFl6UjlPTlZVY3FzOUR5UWxwRzZhQWVvSFN0eVFDUnlYcEV1MjVUNmVLTHgyNnNGMjNsSXNmenRXWVZlaXRWVzJlaEttRXdoc3RxOUZlRmxPd2p2SkhGUWJKMHVJK2NpbjVFY1Nhc2FJV0Y4b2oySlJxcnl5cXRDbFl2WUNOd3JDL090TjVqcUg2aVNhaWVhUmM2c3hPQlR0amNGTkp2cnVKY29JaTFrV2lkaEVlWUdjVnJTT1dJVGJFWWl2UnNWczVGYUxIdTBNaUVSeG91ZG9GNEwrMDJnZWdoN21MOG1Na1RUTWdtSEd6NklJdk1JbEpoZkthRjJJNE1Na1F5c2pHQ3RBb201NG5Va0tKOXNVRDlxbFJpWStidjkvNUE9PTwvZHM6U2lnbmF0dXJlVmFsdWU+PGRzOktleUluZm8+PGRzOlg1MDlEYXRhPjxkczpYNTA5Q2VydGlmaWNhdGU+TUlJRHBEQ0NBb3lnQXdJQkFnSUdBV1cwZERVUU1BMEdDU3FHU0liM0RRRUJDd1VBTUlHU01Rc3dDUVlEVlFRR0V3SlZVekVUTUJFRwpBMVVFQ0F3S1EyRnNhV1p2Y201cFlURVdNQlFHQTFVRUJ3d05VMkZ1SUVaeVlXNWphWE5qYnpFTk1Bc0dBMVVFQ2d3RVQydDBZVEVVCk1CSUdBMVVFQ3d3TFUxTlBVSEp2ZG1sa1pYSXhFekFSQmdOVkJBTU1DbVJsZGkwMU1UTXpPVFF4SERBYUJna3Foa2lHOXcwQkNRRVcKRFdsdVptOUFiMnQwWVM1amIyMHdIaGNOTVRnd09UQTNNVFF6TWpVNVdoY05Namd3T1RBM01UUXpNelU1V2pDQmtqRUxNQWtHQTFVRQpCaE1DVlZNeEV6QVJCZ05WQkFnTUNrTmhiR2xtYjNKdWFXRXhGakFVQmdOVkJBY01EVk5oYmlCR2NtRnVZMmx6WTI4eERUQUxCZ05WCkJBb01CRTlyZEdFeEZEQVNCZ05WQkFzTUMxTlRUMUJ5YjNacFpHVnlNUk13RVFZRFZRUUREQXBrWlhZdE5URXpNemswTVJ3d0dnWUoKS29aSWh2Y05BUWtCRmcxcGJtWnZRRzlyZEdFdVkyOXRNSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQQpvZ2djZmlTUko2UEdvSThYSEtVWWQ4OS9CUE1tZHV6UjM2NXlVRUtTSzZUSU9jQS9qcm5KenhXSFQ5UHN2QjR6bmFvRWRnMjdkbVgwCklaMkkwYmpTb3l2cDRCVDhadHN1cXBhbXNKT0ZEYWpmenJVL2RNTElRQ3dZMCszOEYreC9nTk5MK0JoWWI2em1yZHZvbWI3eXFJMkUKSnVITVhNUzc4NlVZNUdmRCsvbjBnUlN2ZCtEcElXOFpsc1pNRy9sbHl4TzFaY2N1VXF6a2JpVlY0dzF5NVBNdlNCTDdCQVdzVG45RwpJY2tRc3lGK2ZzRzBiS2xOM0pRakhtakZVclQwY25Xa0FKakdJVm1tcnA5TlVXeWMvU0kwMWk2V2x3Y1FzS3c0UEI3RVUzSjhCSU52CjltQ0dYcHdwNXZXWFJkUkdqVFQ0Qm1GbThsWTBRWEhxWGEvMitRSURBUUFCTUEwR0NTcUdTSWIzRFFFQkN3VUFBNElCQVFCeXBGb3gKL0lhVFhBS0ZzUlFpNldVRzBRaUJMQ1I4ZUxoU1VERjN4a2dFTGtOWURFclFLTnlWYVhyWW9Id1BvV1lwb2s2TVlkZE1rb28yWXVQRwpXNlY0ekRhMGswdWxiektsdmJiWlFwa3pJSkVqNGRyK1BhcW10SEFlN0M3WU5rajRqbGZKUDZRZHFNSytyQ0JWVTNrQ1gyYy9BUnVuClZ5L3BJdUxvd1hyUVVDRjBjY2NlUEQ4anJ5ZWorY21tOWpqSFdtUU5mSERNQXYvdnBHU1hWMlczYnpOQUxYeGZDb0txVTE1aWk2WVEKaFhVODVPRTVxWEVZOTJhYjNENjdncHB0ZTdlTm4vRzdEN2N1QVpoa3Q3d2ZMc2pvQ1ZLNGJaT3d4cVV3Nm1Qb1hYRnBrVG5sU284NgpwN3drYmVpaTdFcGptNUhjWFRQUEM3amQ3Wk91M0hzcjwvZHM6WDUwOUNlcnRpZmljYXRlPjwvZHM6WDUwOURhdGE+PC9kczpLZXlJbmZvPjwvZHM6U2lnbmF0dXJlPjxzYW1sMnA6U3RhdHVzIHhtbG5zOnNhbWwycD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIj48c2FtbDJwOlN0YXR1c0NvZGUgVmFsdWU9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpzdGF0dXM6U3VjY2VzcyIvPjwvc2FtbDJwOlN0YXR1cz48c2FtbDI6RW5jcnlwdGVkQXNzZXJ0aW9uIHhtbG5zOnNhbWwyPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIj48eGVuYzpFbmNyeXB0ZWREYXRhIElkPSJfM2I2MWMxYmI3YTQxOTUzNjE5YmRlZjQxMjM4ODFhMGIiIFR5cGU9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jI0VsZW1lbnQiIHhtbG5zOnhlbmM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jIyI+PHhlbmM6RW5jcnlwdGlvbk1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jI2FlczI1Ni1jYmMiIHhtbG5zOnhlbmM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jIyIvPjxkczpLZXlJbmZvIHhtbG5zOmRzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIj48ZHM6UmV0cmlldmFsTWV0aG9kIFR5cGU9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jI0VuY3J5cHRlZEtleSIgVVJJPSIjX2QxOWE1OGQ5NGMxODE1NDA2YmQwMGFlZmQxNzJiODVkIi8+PC9kczpLZXlJbmZvPjx4ZW5jOkNpcGhlckRhdGEgeG1sbnM6eGVuYz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxlbmMjIj48eGVuYzpDaXBoZXJWYWx1ZT4zVmdtUUwzb0hWanZtR1J4WUZveFJKMlpqcks2MDRZaDZnQ2h6K2t2OGEvOFdPd1E5R1dzZkVoWWJsam1jblJFbDh3N25aejZIZW1YZmI2WFRlTWh6Q2JUaVFZSEFjRThBZlVLaHRISGVLZk1RTWV5eTlnZ1pEM3ljT2lWQ0RQKzYraVo4cjY1WUExK24wVnc1WTJUMVJFSXpZOG1FZUdIWkNUVERJb21oRmRPYUhWRkltM2ZSQmREaXFrM0xFRWVvRG11V25uWkJpSnJ1OFNkbDkwcC8xK0x3NXVrNFhDSWd3MDc3Q0Z0WHYxb2MxcnFSUkd5TmhFWHJpWGhLMVdCck5Jemt3dVZZTVRmR0lzalREbFRJVWZUOGNwckY1ZGtQMmFyb1FEMWFlWGtyY2E2VWpYVTV0MkZ2NEYwZ1lSems3TkR2WERaSmxtNTM0Z21MSnB2YWNpQUtKZ3g1VnBpd09FL1VwVFMzbzJzRzBNZnZYUnl2N1MwdkJBSlRKUDdVUmJOczVUaTRQeHN2STV6aUM3Um9RRkZYN3BaWWZxcllCanVrbm00eDNBOFdGYzVjZFdtZEV6eHorUmQwMEpFNXBVN3VJaVZpNlF6S2cramlPWTREUzdVVStGL2pZdEluS0VaSkVFb3AvOVZ0SFJxZ1lqN3pxcGRwZTJ3SjFqcklQY05qcUlXZFY1YUhlajVsazZjWkJIcjBlRnVEWks0WDNNaDVQUnQ5UkVSb1hkbWt1N1M2cG93b0g3bEtEUEpIVEFkUVhUSFZvYXR3ZGI4VTd0Qy9kYVlvbGFrRXk2NVJ2Y01halFtYVJTeDgrVWwvZDBxMGIvUUZoWUh2NVZkTXNYYWRBU0Q0U0lWd1Mwa2FFSloxNmVhQkpPRG1WV1M0Y1YrdUxjUE9VdTZyV0t1NjhpVG9ZUDhESjFZZFNjRjhjcE0xbUNGVGFPNlpjT3RhRUQvRXJMdkJCdnFPOWgwT1EvWVo4TjVSN0hKSnQ3UlRHanV4TjBQMkxpYVcvem1vdTE1b2pySmJyZFRDZWxFV3dyWG5QTzRweXVTc01sL0tETC9JSm9aY3YxTlQ4aStKa2NuOXBQdVZuQ3BXckZnWWRGOWZTZkwrWDNraXd0SjlybjNYaVNvUVh2RUo5SjU4b3dzTWg0bjNFUFVJcnpFT3E1VGVibjVpTmxvdVMyOUhKR3RNeHphOG03UllhcDdkZjExeDE5bStrTDVmc0tnNHRzM1V1TWhVdkovblM5S1VtWWtFOENKdDF1cndWNThEem9EZ3dNTkRmbFphWGRYUmQ1MWtCVVE3Q2lab1p2NFVudkpCQXJNUjhVMHpoOG16M2xqdHpEdGdsVzBFSGNJdFp4b2htUlpLVHZVMXdOa2FHcmtwV3V4aXczSWhKTnF3blZlTG5wWkFvbEt6b1RlWkpjUjVxOHBzNEsvVnhwajhQK3pOcXJJSWpCRUtJbFVyMHl3UjZFbUpLTjFHWXpTaXF3VHdQNGp5MzIrZThuOUVQck9ka0NuWEJhak1pMlV2Rk5mQm05TWVUenY4RGNxWVphZUFhMUp6ZUl4TTd0YVozb0UxSzNYTjBYQ0tPUmJGT01SY2wwSHhQRE9vdDVQb2lDZ0xoeDNxVGJGUHdCcUdkazBmQTZmUDFNWmNMUm55N2lkdVpOQjhINHFBSlo0UU9icHgzSWZNaWxrclpxY29yNXMrMGhHMDBaZFE4YUgwa1lLejJZNDFQaFk5dTRwUXo1NXlhZkJtTGdCamREWDJNNHBiOHRnRmRsMUVyWWtkbW1TeFphNmhWRXk3QUU5Wkh2ZGV5dXZ1cFo0c1NwY1hldm5vMk5SeUVDWmwybHZyZGhkc0N6amJqRFRVM0JIRWczUjFnTTlhOWdJZzg1RklGejJIL3FxcnU0Snppdk1VZmdLdjZHdnpnSXpzWVFkSFhrTklsQkdEMFhSSEZiWGFLWXVYY3MzTDhHNzMrRXhiN1dPYTkzekRKMVNNRCt5cFpNOVNwMVZRbk5Qa2lWeExiTDNxQ01KUUZOQy9jM2theTVINUR1cUt6QjZZbjNtV2FKZjY3YmIzeXNNd255MnBTRSt4eW1BN0V0UVQwbzROWE9hRFQxQVE2bDhxeDNNUW51RUZubWg0L0xZV3FIVUtmTzhETkllR1FZS3BGcHJ4SVp1bVhLQlEvalpUdUF6dUVLUEZRY1hoU2dTM1NNUnAzYXI2aGhPbEs1dTNha0dKUURhYnZsVlZEckt6cDJrVWxoRjlVUnFtQVU0SlNSQTYrY3M2TFQxc1J1czd5V0JleWtsTnlaMnByUUpBV1prVHlaZDVKKzlwb3dvcUhQdGdhN2tEMlFNY0lJTm90QW5IWktnM2Z3UVlhWnJRME5rbUhWREw3akE5SloxUDgvYzdDdzRRMDFnWUIvZmwwVzJKZ3FHZlpnR29kSTdrM3dySmxxYlNQeGt3cWdnVytVSm42d2VGTWV4R0d3dHJseGhid0NhVjVMTXpjNk96dkdkallFM3FKQlhFRkNCdUVJcEozUXRsM2hNcXoxUEZXRXpIcWl1TUlxOG9FM1UyYXAvV2FrOXBtRkNGTll3L1k1Ry9pTE04QUFXRWwrTml3ZFN2N2xVN0wrOHM2NFJKRXJRdHplVFdTR1lneTlaRit5T1E2NUNpMHNaNlJYbEhtZkJMRWo0MHhrY0hrc1NqeHBKc0lOS1Izd0VPcWliSTNKVE1NYUpYc0FCbkhNbWtWanNyR0FQMnBtOVFQempvQ01NY3J0NHM5WDB6T2hKWEhPK2xqTzRVeWpZQkJxVUV3em1tR2V3V01OWVBVQlFrQmJnZlFwYmFNeTR2eTl1SURVWDBOVGRUSGlseUtpR3NnQmtXOWlLcm0yNTl3Ujl2eks2WG55ODcrR1J1TkRIZitLMnFlcy9UVE0xc292aU5oWUJaclV0Q2cyZnovcz08L3hlbmM6Q2lwaGVyVmFsdWU+PC94ZW5jOkNpcGhlckRhdGE+PC94ZW5jOkVuY3J5cHRlZERhdGE+PHhlbmM6RW5jcnlwdGVkS2V5IElkPSJfZDE5YTU4ZDk0YzE4MTU0MDZiZDAwYWVmZDE3MmI4NWQiIHhtbG5zOnhlbmM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jIyI+PHhlbmM6RW5jcnlwdGlvbk1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jI3JzYS1vYWVwLW1nZjFwIiB4bWxuczp4ZW5jPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyMiPjxkczpEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjc2hhMSIgeG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiLz48L3hlbmM6RW5jcnlwdGlvbk1ldGhvZD48ZHM6S2V5SW5mbyB4bWxuczpkcz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI+PGRzOlg1MDlEYXRhPjxkczpYNTA5Q2VydGlmaWNhdGU+TUlJQjd6Q0NBVmdDQ1FERnpiS0lwN2IzTVRBTkJna3Foa2lHOXcwQkFRVUZBREE4TVFzd0NRWURWUVFHRXdKVlV6RUxNQWtHQTFVRQpDQXdDUjBFeEREQUtCZ05WQkFvTUEyWnZiekVTTUJBR0ExVUVBd3dKYkc5allXeG9iM04wTUI0WERURXpNVEF3TWpBd01EZzFNVm9YCkRURTBNVEF3TWpBd01EZzFNVm93UERFTE1Ba0dBMVVFQmhNQ1ZWTXhDekFKQmdOVkJBZ01Ba2RCTVF3d0NnWURWUVFLREFObWIyOHgKRWpBUUJnTlZCQU1NQ1d4dlkyRnNhRzl6ZERDQm56QU5CZ2txaGtpRzl3MEJBUUVGQUFPQmpRQXdnWWtDZ1lFQTFQTUhZbWhaajMwOAprV0xoWlZUNHZPdWxxeC85aWJtNUI4NmZQV3dVS0tRMmkxMk1ZdHowN3R6dWtQeW1pc1REaFFhcXlKOEtxYi82SmpobWVNbkVPZFR2ClNQbUhPOG0xWlZ2ZUpVNk5vS1JuL21QL0JEN0ZXNTJXaGJyVVhMU2VIVlNLZldrTms2UzRoazlNVjlUc3dUdnlSSUt2UnN3MFgvZ2YKbnFrcm9KY0NBd0VBQVRBTkJna3Foa2lHOXcwQkFRVUZBQU9CZ1FDTU1sSU8rR05jR2VrZXZLZ2tha3BNZEFxSmZzMjRtYUdiOTBEdgpUTGJSWlJEN1h2bjFNblZCQlM5aHpsWGlGTFlPSW5YQUNNVzVnY29SRmZlVFFMU291TU04bzU3aDB1S2pmVG11b1dITFFMaTZobkYrCmN2Q3NFRmlKWjRBYkYrRGdtTzZUYXJKOE8wNXQ4enZuT3dKbE5DQVNQWlJIL0ptRjh0WDBob0h1QVE9PTwvZHM6WDUwOUNlcnRpZmljYXRlPjwvZHM6WDUwOURhdGE+PC9kczpLZXlJbmZvPjx4ZW5jOkNpcGhlckRhdGEgeG1sbnM6eGVuYz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxlbmMjIj48eGVuYzpDaXBoZXJWYWx1ZT5yRDl5RUpXdDBRbSt4UURSZXFRVUNEZDN5dEpiWTVtb01zcG5iZzcrY0ZWY1VrN2hVaDRScFpIUldSM2FkWTBRK2drQU1JcUhXYjFaZEFQL2g5emV0RktYVnFiajl4Y2FkSUFnR0UvQWZBMUs5SndXZVZQbmdjeERCNlZ0RU1oZG01cVJEemVnMEJSUnMwTE4xMTRObEN4dHhEMkx5R1c5M0NkZ2t2VXBnYWM9PC94ZW5jOkNpcGhlclZhbHVlPjwveGVuYzpDaXBoZXJEYXRhPjx4ZW5jOlJlZmVyZW5jZUxpc3Q+PHhlbmM6RGF0YVJlZmVyZW5jZSBVUkk9IiNfM2I2MWMxYmI3YTQxOTUzNjE5YmRlZjQxMjM4ODFhMGIiLz48L3hlbmM6UmVmZXJlbmNlTGlzdD48L3hlbmM6RW5jcnlwdGVkS2V5Pjwvc2FtbDI6RW5jcnlwdGVkQXNzZXJ0aW9uPjwvc2FtbDJwOlJlc3BvbnNlPg==`
	test.IDPMetadata = `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="http://www.okta.com/exkppsa1qwuFV4D7z0h7">
<md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
<md:KeyDescriptor use="signing">
<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<ds:X509Data>
<ds:X509Certificate>
MIIDpDCCAoygAwIBAgIGAWW0dDUQMA0GCSqGSIb3DQEBCwUAMIGSMQswCQYDVQQGEwJVUzETMBEG A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU MBIGA1UECwwLU1NPUHJvdmlkZXIxEzARBgNVBAMMCmRldi01MTMzOTQxHDAaBgkqhkiG9w0BCQEW DWluZm9Ab2t0YS5jb20wHhcNMTgwOTA3MTQzMjU5WhcNMjgwOTA3MTQzMzU5WjCBkjELMAkGA1UE BhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNV BAoMBE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRMwEQYDVQQDDApkZXYtNTEzMzk0MRwwGgYJ KoZIhvcNAQkBFg1pbmZvQG9rdGEuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA oggcfiSRJ6PGoI8XHKUYd89/BPMmduzR365yUEKSK6TIOcA/jrnJzxWHT9PsvB4znaoEdg27dmX0 IZ2I0bjSoyvp4BT8ZtsuqpamsJOFDajfzrU/dMLIQCwY0+38F+x/gNNL+BhYb6zmrdvomb7yqI2E JuHMXMS786UY5GfD+/n0gRSvd+DpIW8ZlsZMG/llyxO1ZccuUqzkbiVV4w1y5PMvSBL7BAWsTn9G IckQsyF+fsG0bKlN3JQjHmjFUrT0cnWkAJjGIVmmrp9NUWyc/SI01i6WlwcQsKw4PB7EU3J8BINv 9mCGXpwp5vWXRdRGjTT4BmFm8lY0QXHqXa/2+QIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBypFox /IaTXAKFsRQi6WUG0QiBLCR8eLhSUDF3xkgELkNYDErQKNyVaXrYoHwPoWYpok6MYddMkoo2YuPG W6V4zDa0k0ulbzKlvbbZQpkzIJEj4dr+PaqmtHAe7C7YNkj4jlfJP6QdqMK+rCBVU3kCX2c/ARun Vy/pIuLowXrQUCF0cccePD8jryej+cmm9jjHWmQNfHDMAv/vpGSXV2W3bzNALXxfCoKqU15ii6YQ hXU85OE5qXEY92ab3D67gppte7eNn/G7D7cuAZhkt7wfLsjoCVK4bZOwxqUw6mPoXXFpkTnlSo86 p7wkbeii7Epjm5HcXTPPC7jd7ZOu3Hsr
</ds:X509Certificate>
</ds:X509Data>
</ds:KeyInfo>
</md:KeyDescriptor>
<md:NameIDFormat>
urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified
</md:NameIDFormat>
<md:NameIDFormat>
urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress
</md:NameIDFormat>
<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://dev-513394.oktapreview.com/app/rstudioincdev513394_dev_1/exkppsa1qwuFV4D7z0h7/sso/saml"/>
<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://dev-513394.oktapreview.com/app/rstudioincdev513394_dev_1/exkppsa1qwuFV4D7z0h7/sso/saml"/>
</md:IDPSSODescriptor>
</md:EntityDescriptor>
`
	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("http://localhost:8000/saml/metadata"),
		AcsURL:      mustParseURL("http://localhost:8000/saml/acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal([]byte(test.IDPMetadata), &s.IDPMetadata)
	assert.NoError(t, err)

	req := http.Request{PostForm: url.Values{}}
	req.PostForm.Set("SAMLResponse", SamlResponse)
	assertion, err := s.ParseResponse(&req, []string{"id-a7364d1e4432aa9085a7a8bd824ea2fa8fa8f684"})
	assert.NoError(t, err)

	assert.Equal(t, "testuser@testrsc.com", assertion.Subject.NameID.Value)
	assert.Equal(t, []Attribute{
		{
			Name:       "Username",
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified",
			Values: []AttributeValue{
				{
					Type:  "xs:string",
					Value: "FixedValue",
				},
			},
		},
	}, assertion.AttributeStatements[0].Attributes)
}

func TestSPCanHandleOktaResponseEncryptedSignedAssertion(t *testing.T) {
	test := NewServiceProviderTest()
	// An actual response from okta - captured with trivial.go + test.Key/test.Certificate
	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05 UTC 2006", "Tue Mar 3 19:31:55 UTC 2020")
		return rv
	}
	Clock = dsig.NewFakeClockAt(TimeNow())
	SamlResponse := `PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48c2FtbDJwOlJlc3BvbnNlIERlc3RpbmF0aW9uPSJodHRwOi8vbG9jYWxob3N0OjgwMDAvc2FtbC9hY3MiIElEPSJpZDg0OTM4NjUxODIwNjgwNTY5NDI1MDUxNzciIEluUmVzcG9uc2VUbz0iaWQtNmQ5NzZjZGRlOGU3NmRmNWRmMGE4ZmY1ODE0OGZjMGI3ZWM2Nzk2ZCIgSXNzdWVJbnN0YW50PSIyMDIwLTAzLTAzVDE5OjMxOjU1Ljg5NVoiIFZlcnNpb249IjIuMCIgeG1sbnM6c2FtbDJwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiPjxzYW1sMjpJc3N1ZXIgRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6bmFtZWlkLWZvcm1hdDplbnRpdHkiIHhtbG5zOnNhbWwyPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIj5odHRwOi8vd3d3Lm9rdGEuY29tL2V4a3Bwc2ExcXd1RlY0RDd6MGg3PC9zYW1sMjpJc3N1ZXI+PHNhbWwycDpTdGF0dXMgeG1sbnM6c2FtbDJwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiPjxzYW1sMnA6U3RhdHVzQ29kZSBWYWx1ZT0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnN0YXR1czpTdWNjZXNzIi8+PC9zYW1sMnA6U3RhdHVzPjxzYW1sMjpFbmNyeXB0ZWRBc3NlcnRpb24geG1sbnM6c2FtbDI9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPjx4ZW5jOkVuY3J5cHRlZERhdGEgSWQ9Il8yZTYyMjQxZWU1Mzg5Zjc4OWM2NmI0OTc1NDdmZDkwYiIgVHlwZT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxlbmMjRWxlbWVudCIgeG1sbnM6eGVuYz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxlbmMjIj48eGVuYzpFbmNyeXB0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxlbmMjYWVzMjU2LWNiYyIgeG1sbnM6eGVuYz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxlbmMjIi8+PGRzOktleUluZm8geG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPjxkczpSZXRyaWV2YWxNZXRob2QgVHlwZT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxlbmMjRW5jcnlwdGVkS2V5IiBVUkk9IiNfNDM0MDhiODA0Zjg3MDE2YzdkZTk5MjM5ODFmNTg3MjQiLz48L2RzOktleUluZm8+PHhlbmM6Q2lwaGVyRGF0YSB4bWxuczp4ZW5jPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyMiPjx4ZW5jOkNpcGhlclZhbHVlPktxU3hnbzI4cldjc0pzL0F5K3ZPMHpkLy9CK3EvRHo1ZkZmY3A2cWQ0U0pPbTY4ekxFSEFkTkQ0TFExYjdCdkxrTzYzOW5RZ3JZcWJwM2UvVDNIOEdrSlg2REtHbDB5MnpkdjlJNjRJNUg3K1NFNFM2cjRFWmZlNzJXKzl5bm5FeUR3bmcxLy9FdUlDb1BsOUs4dE9lSTliUTZacjVreUt4OENTNGJFL01CMjJRSGhzc0pUMG9oa2kyTE9LUmg2MTlYbDh6Y1RJem1uZmRNb2tEUm1renNuVmlOa3NaK1Z3ZSt3dkgyUUNnWTFKK28yKzRmY28ya3pGdWN2ZUpkZng4dVRxVFp4dzRhRnRGQ2YvYXprOGpha0ZpazVSN0tZam1mZGxOL0QrOWFDY0tiYlFPMHFxd3AxKzNTNWFiSWczaHRIREIybkNYNnluSWl3S1ozc1B3bzNYVVRsREg2Q1NkTzRFSDVUN3NHcUhRV0ZIN0tLS0lGdHZrMUVhYjI4WXl2UnNrbVJZTXNNUG9tTUZGekt6MlpyM00yY1RBclZDS1dRSzh2RG9laFZyTzZyaHFHbmpCcWxpYkFHZjhleXRpbndEQjgvNm50RnU2aG1LZ0pOdzdFbEpwcU9sQm1ZUE5mU2MxMEMxTjZXS0hqOEZudGVHenE0MmxJdUIzcnFrME0zeGtSdytTYkhxU3FqRDFCbDFDM1gwWlRsMDh6Y2VJbmZ6Vmo1TEZ6YU5iRXFmV0ptRmNOaHhSMGNTekhjelBPT1RzdUlrTEdZZTkxejFkRG1SWTVMNmFyTlhWbzJadjc3NnI1dGgwSVk4cTUva1pjY3pzVERySW1sY1YrTWFtOTZRNjdOOWQ3VVhpVWpUcXdTUjh1TkxVMXpCWFppekpEU0sva25LMDlxZWg0UGxKcHdZcDVab0pLYVp2V0JsV1J2Mm9ZWDJkN3ZyS1kzSVpCanRLWllNQjZpR1MzWUZBbTc3d09xNGs0WWFjSkVBc2ZQaVZqNlJQaTQ4bTZOYnBSZ1ZzMmhZYTE0MzQ2amJqZlFVaWhrTnZ0Q00rM1VlcWU0bGowQVNwR3c3b1hkNVlkQWw4Z3hIc2xyTzNoY3J3Q0JqZTFhOXovaHRYdUU4RldWd2dSODgzbU1tR1hBZ2x1SkNUOUtaaUZvaXpFS0JyaW41NHFpT2R4YzU3ZEVPRmRna05XRXMvdTUwWjZCYWVzaXJvaGN6WFdsUGlWVWFaV0RlTzRzR3p6ajNiaHlPay9MZE53VDJGQ3VvWUlZbC9PWURhUWZVVjdUV3VLeHo5YlRaMVFKRTBMbjQxVjY0QzhGbmpZaldReDhWemFRUkFzVm55NFRSMkJvWmJrQ0VTUHo2eTZRUU1DNG90RC9YcStPMUlzT1pUTlJxNXUzNmo4T0xUVmNIZmdaNTJxVlRnNEJLL01PTmVEM2k3amZsTjNFR05LdGlmMzJkT2lGcTFRY0ZuTXFFL0xFYVJTMHNCdGpUaHRvanBxKzBpNHJrUjVISS9aLzVBOWZHb2hOZkhWa2dEakkvNmdGcGNGQ3lTZWJocEMwRXAzSXA5U09KRmRIQ2tjbjVLNXJYNDlSR0xFTXZtNzVTS05UOVl3RGtOSTlVcWdiQmxGMytMOXp6ZzhhWDFYbm41TWVPSDZCK2lZVlBZYXZkUjZ1WDZYbDVzR0pHRUFUNkNmQVBhdVBGUkNVU2d1LzJiUDlRYzV2Y2ZOeVhmTUJtNGVyTm5jd0NNbGhMRHN4NW1DQWVLdGRWaUxZWTlOclVTNy8vaEp0MmZseEZ5Q29tVXdlRi9pUDZVTVo2ZTV0UHIzK2hVdUZkY0FTMUNsU3FvSDRuVjJVSmVHR3ladC92c1orQmRNdkpoRmp1TEg5REtOVmRtSjFNM0ExRjZ0Ymx6dnFXajlRaVhEV2E2amxhRGxHRXR1NzdHUW5iOTU0MUVMYUZCYnhvRWYvbTNpS1NGUm04REE3NytaanhNUzMzTCtzUldaWm0rNWZJeGtvdUFWR0dGRHJ0M3lQMyt6bWVyWTVPUkN3cW9ZekdyMFRPZGRJS21UcmFrWi9uZnY4a0l1eFpIeUppdHBXSENZTkxMQlhFU3hLaXVKbFRSd0x6U2FWRFhhT3pGVTA2dWxUUVhHOThqazRqU1VhWHR5amV5NGUxT0V0V29oM3ZHVEFRNjczaVY2RlZ3VXdxYzVkQUh2MHV4aVVGaTlXWUsyckpqZ1dLVTN4VDRFZjlWUUZ5OVYrMUhZUDdpalRMWFF4eVlZZjFjTVV5OVlJVGlXbjVIS0ZwT0l6YWxLK2I1R1ZUbWdoZ0F5R0RZTjllOVo1ejg0V3BKN1N0L3FpLzM0a3V5bjRNN21WV2tPRGU4TElyZjkwWnViSk5ObkUwTTdMUldXYXZEUC8wak5OMEtJcW80cnVwRldEN2R3bDNKQWlSbzdJcEl0Rm0vQkpGb1hDWmZFTUgzOUxqL3dZNFF4Z2NuRFRKbmo1bGdUK3cvT0xvN1hJYlZRRHhjaE9WUkVqTWtKM3lKa2VmSktNUFFQUThGMGpKZ1NmM3VraWpuaTlSbG5Pd2EvVi8wVnF4RCs5NUtwNDhiMU5MR0FLN2hidVFZM3c3VFlzZWtteWZlbzRqbGZqWkZYWmFyTUExQWJ6cENvMTR2K2FCcGhnYXNzVjBjTDlxL0FyVERlK0pJM2c5Q09pN05PYm5FOHVhYjl3Z3FETzFCV1lEQ0Rnc2Z6WXFiRU9kYlE4SHZtZlBIaks5Nit3Tk55K2lDSFBvcnFiRzA1SDFsZHJyb2hVKzhkeklnOVkwMVlCc0RIUkVCU0lZMHU0QjdIYXMrQ1RnS2hSaysyQ3lWcmF0U3ZHWStuQkF6U0U5enBkTWpKbEJWaTRxeWgwcHlKeU1qQ2xESzNBMGxCYjlGd0M4RWpEdjVpbTMxZWJLMmhBQTJTRVBYZC91N01DeG1veDhKYVJBZzBxTVorZGtMZnpqNjBlUWlBalp1dGhNZ1prMWhiVzl5ZFordmRwRlBoeFVHTzd1QTA1ajc4QjkyRUxCYkxCWTMvZ09tMEplN3QrTmorTlMvbHZRN1Q4RytpT0lFZnY1S2ljU2M4dE1vWUVRWEtrK3VyZVFDQzBpOG5sOXZEdWFLMTNyNTZkM0YxMGxHN284SDYyR0ZBQm1rNnBlMVVZdDdWL3dwM2xPR09TcVBkUzJ1Q3hlR2g0aWNHcHJYeDNod3lmT3Q0TTErMnhvMjhkbHJqREtuOEhaTTZnTGRUcGlhMVc5WTFIallMNDdCcU12OEpuZGhQd2RTWkduUGhlWjJQQ00wN010bmNlRzBsemNBQmhJYUU4R0tDZ2RaRXpuODlwK3gwbVhtT2JOckJ4MTRKQU9Dd2F0N2tZdk5IS3VwckNrK1g3aW9pUTJmZmRzTkxOYktyZTdHT3cyRmZ0OUVXQU95RCsxQlFBbW4wdVI3NFBoSUJQTmFGN1o1dTdEYnRBZnV4cXR4Ym9ReFpEM1Q5M3ZWNTBnUFdIcHlVbHBRTUQ3ZEhiNVZ6aDlNWlFQYnNnSWhxeGV6U0x1dlI4dmFMT1lXbGxQcTFLTUY5dkZaNWl3U0Rjd0VTVGlXV3owNnRUMlZvZTRud2FxQk40MkhiTmVFdy9kMVpvNUR6Ujg2ZmYrQjE5c3crbGZZNTVHU0NkcENTM2kzWi9oRTVuNEZ6czhLdWhSTHlJaExKQTlYY3RTcjdyenljUFpyekhhN29QWFM3eUtCalRZVFN0ZTIzYVEvM2swQ2hoVXU5TVBzdlBiekNzV0NTQ1NtdFFZNjJtQy8vdVVQR1lFZUUxclZIWU9BeS9uWU9sc2R6NXc1Myt3VnVtVFVjTUx0V0hob1dsSVJEVlRhVklRL0FGcC9DbHpzV3lvRC90TlRoZ2Z2VlUrcVN3eTRvRVVVWHorRm9rU1dXYWFtRG11TkRFL2dJTUxWcExXNUd3UHdDWWFrNi9NUkJtVDFoVW1vdHVSL1hRUHpveElEc0UzZjQyN3V3amF0WW1wMGVqYUtWMVNXbG1NYVIzNmQ3MkJLQVovNHdvQkFXYXA3M05UVEFlZ25SL25EclZwRnNZbVpySFhQNldYaTNmY2dSWkR1QXNFdHg3R0tLNlNmMTlIMExoSVhiTXRiS0c1KzhRZFE4MnpjRW01bURreW9Ha3B2dzVuemhYNy9MOWV6SGY0Yiszcm9YU3dYTHVRRmNlT3RyZlkxb3FSWFo1YlI0MDdabXJiTTA1cXBVdUdNOThweHZybjgxaldvMXpxQ0lmckJORGNPN1hDZXVoS2JWTlJObis4TGJmV2FjMStWeUh2bUNScDJRTWxiTDVvdndodFM5UXhTSTQzRUpJbU4vczJVUS9JYVFXZXJYYVFJZjg1SEs1bjVaeTBqOWxBNFN5MlQzTXVnOXBSNitNU1RyWWNnRjVneTBxdzdEUWRoRTlhS3ZqSUY3REUzK0YwU21peHF5UzNBODBzeTZKUi96NlE1dDJKb3FjSVcyNTZHb2JXaEFYdytOWk9aT29ROXVEbkJnQ3E3VC9qcVMxamFhVlUxNVJ1TUNDSnpBTzlYSHpPVENxcURPeitMLzVqaU1xODd0ZThRTy8vZGlTVlErY1VaeHYxcGxmWURBRUpoUWtscG43eUpYdVJBVDE3S0xmbXRlaGJQNHBLM0hQNnVoZ3BFa2hZVHNHMlhweGg5VVluckQ0WTFSSzZXS2pPUDFWSzlWRU5FZ3FlMUhVTlZBbmQ3U3pUWVFnQWd6RHRuYWltNytYT1JNMEpVOFpwZWZBZ2Z6cTZtT1JIV2d6S252YTU4czVQeUYzSWk4dzN0ZmlCaEtZWjRFK3ZaVVF4NmFLUEgyNVp2U2ZYampvcDlXZ3hKN043d053WTVzZjlKd1UydnhHV29OdjVwbm84dlFKeXRkbzVzN1B3Z0NJd0FkZE5UbEZ1WEJVMEQ5aVphM2JUVUMyRHl1RFVkaGJqRkZPeldzQmR4R3h1eWYzbmtnZEhvTVBxREpYeStvKzRBU2MvZkRxbHFsaUJXa05TWmx5UWdieDJKY05BQzR0Zmw5OW9iNjl5Yyt3ZXVHU0p6YnEyM1U3Vk1HUUVObWxaR2Q5aHEwZVdCempRVVVWY3dzbHVLNk5uZTBoTk12djl2MUNoMW5sOXJna1I0bG5FWEUyQ1hhcW8xVWQ5bVdMVVJBUFZkdk9YWmNINHhiRzF2WEVPRUMxNVhBaTd0Ni9weEVkcGJLLy9rOWE2NFBld29KU0UxcUtSVGh6RmxBUTU4UzZPL21YNWJhdG9WbXo2ak02Zi9TbjFlQUVBdHFHdEFsY0lGZWNCejN2OGR6SE4wcGZrRk1lNnRLYjcybTZEYkpZVnA1blZYVjBKSjVkYjMxcXQrUVRkelp4eE5TWkJ3NUlGSXd3MXNtcnZpRmwrSUhQZlpMK1VNUUtZTk5seE8xRWxmcGFoTGpFMmtLSUQrYjkvWE9wZDI0UVA1YzZnTjJzNjNNZE92dVYwTzhqVGkwNXYxL1g0cGZ0aDYxNjl5bUZ4Q1Q1ODdMRzNscUw5T3QwbEVqODd3aEkxZ3gvTlNQcGRzWGZHSWRoZlY5MmtaT2cvQVhvZkJpb1NHQ0JYc3ZvZUdlMmFCdUZkSFFZUzJkcVl0d1Zta0F5OWhnUnA2N0paQ0FIRTJRaUIvdTRJQ0ovd3duNFduc0VBa2VIbmdlWDVZR0Y0azJwYmZqakVXbWxSWmFJVjVQSmFaU1B4TGpPWWdLb1pqZGx3L1B2cDdEWXRTVDdrTnNIRlU1WFgzNnFXS3Q2WEpaWGlDN0hJR2ZxQmtIdjhjWEdwYjExcitMNWJaZ2NvMWhzQ0ZlQ3JmamFWcnRhWDBtYjNOaUpsOGQ4ekhCcXRWSVRKMGtPNVQrU2JYZmVBa0NuQWFTUmp6QXNrdDd3b3kyY1BFVGk0eTlDQnlZYnZrWHJ5Q3RhQTgxNC9sY1FoWG9jQ1Fscmg2bVYxd0kxOS9VdFBsTnRQcUVyemtFK2QvT0tYWmtEUExydWJZQnhZQ21yb3VRVm9QMEwyQWc2TGErV2VVeTh4dm5mKzRrR2xnUittdDh6UjYrd1cvdWNvNkViK21RMVVTRTdiYVVDZXFsVjJNaVl1Yk4vMVp3MWNPNUFrcU05TlJaeG5RdUJWMXZiak5JbmhwNDgzTDJiOVAwa0RSNUJleFVDNnErL0E3NXpYNG5NUHY2VHhWWFRwV1Rrbzh2OXFQbWZQUkJhaGs2czdDbXY1M0ZkbE10RHI5cThheU9YRHBjbzRSbzlSMmpoWk9SOFM3bE0yRzNKZkxTYUpnUXBFa25kcnkrMjRBZVpFZXEwSGJoakNUVzM2TjJLeHdSMmxxbGg5Smk4WWJ5ZDd1eVlSenI0YmNmQ2lDZEVVSGhUSnJXM3BoLzU4VmVpTCtkcjV4eVdhVVBDMk5RTnFFcUlFa0w3Y1N6ZENkOUlwenY3N3ErMHdXT29xaGxua1dUK3dOeEZVaitidU03M1Z6aE4rb1poVlhZZHcxZitIZGtjY21IQXBWS2tXUVc3YUw4cllaelUycjdzQWlDMEsxNXg0WHZqdDV5ZEJhQS9HcU02MmhjZ1dXZlFmZW92MS9ZMmVFblA4Ykcycy9KZ0dlcEROcXJrQVpTR0J4NDlNUVdyYnNndEFLc3YvMGpHL2VUYXVmN3J2dDRMK29JOXFET25ZMTFzTnBSa3ByVDRKZCtlN3B4a0NlMmhoaWtsZWxZbXM2MDlXaDU0dWI4T0oyVGE1L0dnT3BKZHQ4Y1JrNXpKT1hLZGdGUDNTaWFVQjIzYXJ3TEEwS3U0cCtNUGNQOUdUeGdsSmxrK2N3QVRPVXRTL1pnYURQRnB1dTFBeXBKUi9RTUdMZ0JDbStxZkk5ZURqbWMxTXcyQXV0ajJ6Z2xrYnFtb1dadWdPTWdYZFZrSG5SU0ZOdmFqbUJId1lvc0dBWVZCQS8zM3o0QkFIZHp3aFZXbkZQUGF3b1FKcUJCaVVBeGFIOGxjeEpTVXdWUUMvaFoyQSt3TXNmdEtoOHpaeE43THJDakVEa2hON0l0NFFjcEVJYk50UG5oZ0JBWmR5TGo1YTFVUHRMY2llL3o2SGFLTmFxcUtvZjFTMll2RmlhemZLcjdnTGdkRXE0UHdKOFVrS2lIOER1TmthVWRNSDZ5cjd4Uis0SFVVRUhaRFpkbytLMWRxTnlGZWhJZ3dGM29BWE4wcFBQQ0ZjR0RYb20zWVkrWGw1RWRENTVDZEV3bUF6T3FCNDNCaTdtQm9kZmVTdXRKbG9YTlAreUpLSDJKemNuUE1wWDJpT2d5MmdwNGM0SThqdkJpSmp1bHJ4QTBsWW9aZTlXZUtkSVNQOHBkSzQxUFdwd2pkMnVPQ2VOcDZYaHNVbHZvWis0WHV4d2Q5MWRNZjJlQ2tJQUdMaHFsZUpIako3L2haa3JOTTVoYWJreGhnVGk5NVJkZ0Vzay9mR0lOS08yVTRKVXZPSkE2eUkra0QrOXRmbUxSVi9QeFhROGluZEtPWnZnYXk5MEErT3pVR1B2Mmc2UUJzSi9pR1laeVgwOE5QSFg4Wit4eGJRcTVnU0l6bkxkZ1ByTUZjWVZCeVl2Y3dMRytyTWZRcEt1eVV0Wk1WL0JCV3BXSFNxaE0rMkRwN0N2M3JYS3QzMjFnb09ZdzlPOEtzV3BhU29RSDJvU2c1Y2VBcW1TU1hUbGJyL1YramZEbjV0TldJVG9SZXpkVU5vQUVnbHJRbFJ4eHJlbklCN2xMUEFJVS9BbW1LYXVsb0V3dEl4eXJuRWRNL1A1QlJ1Q0JkTTZ1ZzNrOVJLYzlwNEVCcnZJempreEFsZzNva2VrQjhkWDh4UGhLZXd4dDBidm5yWWlsdXZSb01rSEpjYkJuelVvM2wvbjZBUmZhTUlnSDVRU1RhdFBiYmUvSlhrOHd1UG9iZVNocTFjT0ZOVFhET2VvRHNCbXNRS1RIeTlXZk0xano2R3FXYXk0VkFoYjh4NVllL1ByZ1VFVFZyeWFnRWNNUzZVdXJYODByUUZUTHltSSsweW9ORzIwcWxCVE12Ujl1dUwwVmVmYU9VaEI3NFFjS0lOajNMWFdRSytSTENpcmZMZFB4WGRhdz09PC94ZW5jOkNpcGhlclZhbHVlPjwveGVuYzpDaXBoZXJEYXRhPjwveGVuYzpFbmNyeXB0ZWREYXRhPjx4ZW5jOkVuY3J5cHRlZEtleSBJZD0iXzQzNDA4YjgwNGY4NzAxNmM3ZGU5OTIzOTgxZjU4NzI0IiB4bWxuczp4ZW5jPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyMiPjx4ZW5jOkVuY3J5cHRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyNyc2Etb2FlcC1tZ2YxcCIgeG1sbnM6eGVuYz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxlbmMjIj48ZHM6RGlnZXN0TWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI3NoYTEiIHhtbG5zOmRzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIi8+PC94ZW5jOkVuY3J5cHRpb25NZXRob2Q+PGRzOktleUluZm8geG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPjxkczpYNTA5RGF0YT48ZHM6WDUwOUNlcnRpZmljYXRlPk1JSUI3ekNDQVZnQ0NRREZ6YktJcDdiM01UQU5CZ2txaGtpRzl3MEJBUVVGQURBOE1Rc3dDUVlEVlFRR0V3SlZVekVMTUFrR0ExVUUKQ0F3Q1IwRXhEREFLQmdOVkJBb01BMlp2YnpFU01CQUdBMVVFQXd3SmJHOWpZV3hvYjNOME1CNFhEVEV6TVRBd01qQXdNRGcxTVZvWApEVEUwTVRBd01qQXdNRGcxTVZvd1BERUxNQWtHQTFVRUJoTUNWVk14Q3pBSkJnTlZCQWdNQWtkQk1Rd3dDZ1lEVlFRS0RBTm1iMjh4CkVqQVFCZ05WQkFNTUNXeHZZMkZzYUc5emREQ0JuekFOQmdrcWhraUc5dzBCQVFFRkFBT0JqUUF3Z1lrQ2dZRUExUE1IWW1oWmozMDgKa1dMaFpWVDR2T3VscXgvOWlibTVCODZmUFd3VUtLUTJpMTJNWXR6MDd0enVrUHltaXNURGhRYXF5SjhLcWIvNkpqaG1lTW5FT2RUdgpTUG1ITzhtMVpWdmVKVTZOb0tSbi9tUC9CRDdGVzUyV2hiclVYTFNlSFZTS2ZXa05rNlM0aGs5TVY5VHN3VHZ5UklLdlJzdzBYL2dmCm5xa3JvSmNDQXdFQUFUQU5CZ2txaGtpRzl3MEJBUVVGQUFPQmdRQ01NbElPK0dOY0dla2V2S2drYWtwTWRBcUpmczI0bWFHYjkwRHYKVExiUlpSRDdYdm4xTW5WQkJTOWh6bFhpRkxZT0luWEFDTVc1Z2NvUkZmZVRRTFNvdU1NOG81N2gwdUtqZlRtdW9XSExRTGk2aG5GKwpjdkNzRUZpSlo0QWJGK0RnbU82VGFySjhPMDV0OHp2bk93SmxOQ0FTUFpSSC9KbUY4dFgwaG9IdUFRPT08L2RzOlg1MDlDZXJ0aWZpY2F0ZT48L2RzOlg1MDlEYXRhPjwvZHM6S2V5SW5mbz48eGVuYzpDaXBoZXJEYXRhIHhtbG5zOnhlbmM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jIyI+PHhlbmM6Q2lwaGVyVmFsdWU+Y1dtRmZHU1VOM08rTGJxd1ZpbnJvMWlmZEJYNTYxOFdtRlI4KzJKQjRqUTdYSndtb1NlNG8yNTQxbkkrUStaL2R6MmhOUFc4bmF5MzdvUkRDa1RocnY2Q0RjZlFhYjBmZnFWUFUreGVrVnd0ejRBSWc5bWt0UFdSempnaGdCdUliU055aDJDZU45dUlwOWJwbVpYY09ScEZoZzMyWVpxRWhEUWxmMWdTUEpNPTwveGVuYzpDaXBoZXJWYWx1ZT48L3hlbmM6Q2lwaGVyRGF0YT48eGVuYzpSZWZlcmVuY2VMaXN0Pjx4ZW5jOkRhdGFSZWZlcmVuY2UgVVJJPSIjXzJlNjIyNDFlZTUzODlmNzg5YzY2YjQ5NzU0N2ZkOTBiIi8+PC94ZW5jOlJlZmVyZW5jZUxpc3Q+PC94ZW5jOkVuY3J5cHRlZEtleT48L3NhbWwyOkVuY3J5cHRlZEFzc2VydGlvbj48L3NhbWwycDpSZXNwb25zZT4=`
	test.IDPMetadata = `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="http://www.okta.com/exkppsa1qwuFV4D7z0h7">
<md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
<md:KeyDescriptor use="signing">
<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<ds:X509Data>
<ds:X509Certificate>
MIIDpDCCAoygAwIBAgIGAWW0dDUQMA0GCSqGSIb3DQEBCwUAMIGSMQswCQYDVQQGEwJVUzETMBEG A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU MBIGA1UECwwLU1NPUHJvdmlkZXIxEzARBgNVBAMMCmRldi01MTMzOTQxHDAaBgkqhkiG9w0BCQEW DWluZm9Ab2t0YS5jb20wHhcNMTgwOTA3MTQzMjU5WhcNMjgwOTA3MTQzMzU5WjCBkjELMAkGA1UE BhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNV BAoMBE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRMwEQYDVQQDDApkZXYtNTEzMzk0MRwwGgYJ KoZIhvcNAQkBFg1pbmZvQG9rdGEuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA oggcfiSRJ6PGoI8XHKUYd89/BPMmduzR365yUEKSK6TIOcA/jrnJzxWHT9PsvB4znaoEdg27dmX0 IZ2I0bjSoyvp4BT8ZtsuqpamsJOFDajfzrU/dMLIQCwY0+38F+x/gNNL+BhYb6zmrdvomb7yqI2E JuHMXMS786UY5GfD+/n0gRSvd+DpIW8ZlsZMG/llyxO1ZccuUqzkbiVV4w1y5PMvSBL7BAWsTn9G IckQsyF+fsG0bKlN3JQjHmjFUrT0cnWkAJjGIVmmrp9NUWyc/SI01i6WlwcQsKw4PB7EU3J8BINv 9mCGXpwp5vWXRdRGjTT4BmFm8lY0QXHqXa/2+QIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBypFox /IaTXAKFsRQi6WUG0QiBLCR8eLhSUDF3xkgELkNYDErQKNyVaXrYoHwPoWYpok6MYddMkoo2YuPG W6V4zDa0k0ulbzKlvbbZQpkzIJEj4dr+PaqmtHAe7C7YNkj4jlfJP6QdqMK+rCBVU3kCX2c/ARun Vy/pIuLowXrQUCF0cccePD8jryej+cmm9jjHWmQNfHDMAv/vpGSXV2W3bzNALXxfCoKqU15ii6YQ hXU85OE5qXEY92ab3D67gppte7eNn/G7D7cuAZhkt7wfLsjoCVK4bZOwxqUw6mPoXXFpkTnlSo86 p7wkbeii7Epjm5HcXTPPC7jd7ZOu3Hsr
</ds:X509Certificate>
</ds:X509Data>
</ds:KeyInfo>
</md:KeyDescriptor>
<md:NameIDFormat>
urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified
</md:NameIDFormat>
<md:NameIDFormat>
urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress
</md:NameIDFormat>
<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://dev-513394.oktapreview.com/app/rstudioincdev513394_dev_1/exkppsa1qwuFV4D7z0h7/sso/saml"/>
<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://dev-513394.oktapreview.com/app/rstudioincdev513394_dev_1/exkppsa1qwuFV4D7z0h7/sso/saml"/>
</md:IDPSSODescriptor>
</md:EntityDescriptor>
`
	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("http://localhost:8000/saml/metadata"),
		AcsURL:      mustParseURL("http://localhost:8000/saml/acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal([]byte(test.IDPMetadata), &s.IDPMetadata)
	assert.NoError(t, err)

	req := http.Request{PostForm: url.Values{}}
	req.PostForm.Set("SAMLResponse", SamlResponse)
	assertion, err := s.ParseResponse(&req, []string{"id-6d976cdde8e76df5df0a8ff58148fc0b7ec6796d"})
	assert.NoError(t, err)

	assert.Equal(t, "testuser@testrsc.com", assertion.Subject.NameID.Value)
	assert.Equal(t, []Attribute{
		{
			Name:       "Username",
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified",
			Values: []AttributeValue{
				{
					Type:  "xs:string",
					Value: "FixedValue",
				},
			},
		},
	}, assertion.AttributeStatements[0].Attributes)
}

func TestSPCanHandleOktaResponseEncryptedAssertionBothSigned(t *testing.T) {
	test := NewServiceProviderTest()
	// An actual response from okta - captured with trivial.go + test.Key/test.Certificate
	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05 UTC 2006", "Tue Mar 3 19:40:54 UTC 2020")
		return rv
	}
	Clock = dsig.NewFakeClockAt(TimeNow())
	SamlResponse := `PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48c2FtbDJwOlJlc3BvbnNlIERlc3RpbmF0aW9uPSJodHRwOi8vbG9jYWxob3N0OjgwMDAvc2FtbC9hY3MiIElEPSJpZDg0ODk4NzY1MjE1NzUzNDAxOTcxNzMyNzQ2IiBJblJlc3BvbnNlVG89ImlkLTk1M2Q0Y2FiNjlmZjQ3NWM1OTAxZDEyZTU4NWIwYmIxNWE3Yjg1ZmUiIElzc3VlSW5zdGFudD0iMjAyMC0wMy0wM1QxOTo0MDo1NC42OTlaIiBWZXJzaW9uPSIyLjAiIHhtbG5zOnNhbWwycD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIj48c2FtbDI6SXNzdWVyIEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOm5hbWVpZC1mb3JtYXQ6ZW50aXR5IiB4bWxuczpzYW1sMj0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiI+aHR0cDovL3d3dy5va3RhLmNvbS9leGtwcHNhMXF3dUZWNEQ3ejBoNzwvc2FtbDI6SXNzdWVyPjxkczpTaWduYXR1cmUgeG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPjxkczpTaWduZWRJbmZvPjxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PGRzOlNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZHNpZy1tb3JlI3JzYS1zaGEyNTYiLz48ZHM6UmVmZXJlbmNlIFVSST0iI2lkODQ4OTg3NjUyMTU3NTM0MDE5NzE3MzI3NDYiPjxkczpUcmFuc2Zvcm1zPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjZW52ZWxvcGVkLXNpZ25hdHVyZSIvPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48L2RzOlRyYW5zZm9ybXM+PGRzOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jI3NoYTI1NiIvPjxkczpEaWdlc3RWYWx1ZT5qSkxWRHRsRjNlTzl0ZHdaZVJxUWdIR0hLMHJJNWxXb1J2VHBDS3dIWGUwPTwvZHM6RGlnZXN0VmFsdWU+PC9kczpSZWZlcmVuY2U+PC9kczpTaWduZWRJbmZvPjxkczpTaWduYXR1cmVWYWx1ZT5tUTJ1SEJWdVR1YTMxNHozTnBWMEZ6RC9CUFFUL3JuZWZLcGc0bnlDYXp6RjM0Mk9LaFN0Z1Z5NHZTbVJFUmpVRnFkUjV0SFpLWlJQZWxwVEFPS01kZmxXNlV6QnphWDBpSTgwKzQ3Rm02akNtaVN3RUhyaUVIMWRBblVPZWM5MytSTzFYb2xFSlo0aXF2L3N0VTNvSS9KamlzU1VHeVVhZDVwZFA1NGFLSzZ3cDFjRW95ckxmOEVYRDUvYjREb1U4elVHZWdXdEw2NVpMYkVSWWZkL0hGWVRhRWkzVjlpalJ2SDN3WmlGeWNqNXI4YjRvWUZPOWFZaWZOOXlmMnF6QW1NTUcyS0M1R0RNUWk1WFZJbVBVVS9DeDg4SUFIbHN3TkMxZFRrUDhkOW9lRDBLeFVaQU5xTDcxZGNOTCtuU2Yrd2dDN09xMTdYSDRtcHg1YnpXMGc9PTwvZHM6U2lnbmF0dXJlVmFsdWU+PGRzOktleUluZm8+PGRzOlg1MDlEYXRhPjxkczpYNTA5Q2VydGlmaWNhdGU+TUlJRHBEQ0NBb3lnQXdJQkFnSUdBV1cwZERVUU1BMEdDU3FHU0liM0RRRUJDd1VBTUlHU01Rc3dDUVlEVlFRR0V3SlZVekVUTUJFRwpBMVVFQ0F3S1EyRnNhV1p2Y201cFlURVdNQlFHQTFVRUJ3d05VMkZ1SUVaeVlXNWphWE5qYnpFTk1Bc0dBMVVFQ2d3RVQydDBZVEVVCk1CSUdBMVVFQ3d3TFUxTlBVSEp2ZG1sa1pYSXhFekFSQmdOVkJBTU1DbVJsZGkwMU1UTXpPVFF4SERBYUJna3Foa2lHOXcwQkNRRVcKRFdsdVptOUFiMnQwWVM1amIyMHdIaGNOTVRnd09UQTNNVFF6TWpVNVdoY05Namd3T1RBM01UUXpNelU1V2pDQmtqRUxNQWtHQTFVRQpCaE1DVlZNeEV6QVJCZ05WQkFnTUNrTmhiR2xtYjNKdWFXRXhGakFVQmdOVkJBY01EVk5oYmlCR2NtRnVZMmx6WTI4eERUQUxCZ05WCkJBb01CRTlyZEdFeEZEQVNCZ05WQkFzTUMxTlRUMUJ5YjNacFpHVnlNUk13RVFZRFZRUUREQXBrWlhZdE5URXpNemswTVJ3d0dnWUoKS29aSWh2Y05BUWtCRmcxcGJtWnZRRzlyZEdFdVkyOXRNSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQQpvZ2djZmlTUko2UEdvSThYSEtVWWQ4OS9CUE1tZHV6UjM2NXlVRUtTSzZUSU9jQS9qcm5KenhXSFQ5UHN2QjR6bmFvRWRnMjdkbVgwCklaMkkwYmpTb3l2cDRCVDhadHN1cXBhbXNKT0ZEYWpmenJVL2RNTElRQ3dZMCszOEYreC9nTk5MK0JoWWI2em1yZHZvbWI3eXFJMkUKSnVITVhNUzc4NlVZNUdmRCsvbjBnUlN2ZCtEcElXOFpsc1pNRy9sbHl4TzFaY2N1VXF6a2JpVlY0dzF5NVBNdlNCTDdCQVdzVG45RwpJY2tRc3lGK2ZzRzBiS2xOM0pRakhtakZVclQwY25Xa0FKakdJVm1tcnA5TlVXeWMvU0kwMWk2V2x3Y1FzS3c0UEI3RVUzSjhCSU52CjltQ0dYcHdwNXZXWFJkUkdqVFQ0Qm1GbThsWTBRWEhxWGEvMitRSURBUUFCTUEwR0NTcUdTSWIzRFFFQkN3VUFBNElCQVFCeXBGb3gKL0lhVFhBS0ZzUlFpNldVRzBRaUJMQ1I4ZUxoU1VERjN4a2dFTGtOWURFclFLTnlWYVhyWW9Id1BvV1lwb2s2TVlkZE1rb28yWXVQRwpXNlY0ekRhMGswdWxiektsdmJiWlFwa3pJSkVqNGRyK1BhcW10SEFlN0M3WU5rajRqbGZKUDZRZHFNSytyQ0JWVTNrQ1gyYy9BUnVuClZ5L3BJdUxvd1hyUVVDRjBjY2NlUEQ4anJ5ZWorY21tOWpqSFdtUU5mSERNQXYvdnBHU1hWMlczYnpOQUxYeGZDb0txVTE1aWk2WVEKaFhVODVPRTVxWEVZOTJhYjNENjdncHB0ZTdlTm4vRzdEN2N1QVpoa3Q3d2ZMc2pvQ1ZLNGJaT3d4cVV3Nm1Qb1hYRnBrVG5sU284NgpwN3drYmVpaTdFcGptNUhjWFRQUEM3amQ3Wk91M0hzcjwvZHM6WDUwOUNlcnRpZmljYXRlPjwvZHM6WDUwOURhdGE+PC9kczpLZXlJbmZvPjwvZHM6U2lnbmF0dXJlPjxzYW1sMnA6U3RhdHVzIHhtbG5zOnNhbWwycD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIj48c2FtbDJwOlN0YXR1c0NvZGUgVmFsdWU9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpzdGF0dXM6U3VjY2VzcyIvPjwvc2FtbDJwOlN0YXR1cz48c2FtbDI6RW5jcnlwdGVkQXNzZXJ0aW9uIHhtbG5zOnNhbWwyPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIj48eGVuYzpFbmNyeXB0ZWREYXRhIElkPSJfNThkYTEwZGU4ZjhjMzBlZWM1NmY0MWU4NjQzZDA3NzkiIFR5cGU9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jI0VsZW1lbnQiIHhtbG5zOnhlbmM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jIyI+PHhlbmM6RW5jcnlwdGlvbk1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jI2FlczI1Ni1jYmMiIHhtbG5zOnhlbmM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jIyIvPjxkczpLZXlJbmZvIHhtbG5zOmRzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIj48ZHM6UmV0cmlldmFsTWV0aG9kIFR5cGU9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jI0VuY3J5cHRlZEtleSIgVVJJPSIjXzdkMWM1OGFkNDIzYTdiNDM4MTdiZGFmMWU5ZGI0ZDRmIi8+PC9kczpLZXlJbmZvPjx4ZW5jOkNpcGhlckRhdGEgeG1sbnM6eGVuYz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxlbmMjIj48eGVuYzpDaXBoZXJWYWx1ZT5tbnBtYS9PL0ppdkZEaXhnOC85K0xVMlJTVXJzVU0yOUZEVEhYdkNFbGVoVzB0ZFNwUzQxOTBOaHEzbm8yMU53TjBQZ3RGTUdkUE84eEMvbEhwOXRqcXFEejBjTHh1NzVyVzlmL3hLbEhja0pYTXBxOVJmL1UyTHN3SUltMEtZQzREcXorQ3U4djlhRVA4YlB0Y3krQnQ0bm5MV3lvQlFzNnpxbW5YNmltTWkwaGNVeDhGaVYyOSsxTmRvOU5VelFxdGo4cngrYS82RGlRVjBoMjJOS2MzSHN3VlEvbWhzOVcyelFjZ0tvSldBWDV3dmIxYlVKcDNmZkJIUnVwWmZLdUh4SCtnYkNYcU9naFJpNXh3UVVMTmw1RzVLYzZhQmxGSTdxL3Ntcml3a1VlS1NUYjRwakN4MmV2d0Q4KzRobDRxem5TREN0R05TOUM3QjRnNm0zSWpkY2ZSNWd0TElKS3lVdGxpaVFzVVl5UThOc1YyaUMraUlONjRVSStJUU5CZXRNQm81WDd2RlpZenNRVm9yNUc3a1JGRUk5SUdFTFBHOGRpOFZrL3krSWJ4aldnQU5IUHBKeDJER1BUOWJZazlpc01lT21ib1FZWE5tcjBJUWsreUtOQThwTXNWK2pYSERqTnJDY3lPcTA4OXcyWjJWeHJUT3JMeHNRdVM0c2RzMTVVNk5VaTFBUXE5TUQrbWs2ZkxrOW9NNVhrV0MvUThLM2ZXNG5aZFJhTnhIb0NoaXhFc1ZXeGRVU3IvNENtSWtXSVRqUityeTcxRXJnK0JzY3JvVUJZTDNUMHBaeWdkaTd6d1pqNW0zZjE0cDRsazZpWStIZ1hzaVRLSjhsYXdWTEQ4cHFENDZzT0RkcFc1TVBDRHJ1Uk90WjZsb2dJeXJVZkd3cnh5dzJsbzlGRktYMklJamNMN3hKT3FCbmUzaldocHhTcjJjMjVJQXkrblBPVkFFMlVFSEh6a0RLcWd4bktySDZGUVhkZGdlMVdNcUt6b1BWYjRhd0hmTW9OaURHeGVURjNCWGFXcDhnSEJiOUJ0WGg1MlB4d0xTMWJvb054TjBRZ1ZOOXpaby9JOWp5aXc2d0pPbDBHV3BKaktPamFkYkl1bEJQQzlDZkJPOTJxWXhuV1RnMTRGZTV0emt5SmFEbkRjUmMwUldBQnlFRzlHNkIycUpSRU5Dc25MVjlmWG1jU0RZZmp4UGszK3hVaUYzQjdCQTlvUVBQcDJMU0JSWU1QcjExUEJZaHFHU2o3Y2hGSm1iT0FvUmFtVy9idU9IQnZKN3lCVnhiUjlhRjR0VTIrMWxTdHJ4aGZNandJQllZaWNIRHBHUDFSMTVPYk9GV2hsY2NSay9kWDdWcEhvcStQSVdXRm5tMjZRcHprYWE3UytWUXdZcVNjaVJvajZadXVBcm1nQkNtTytPU1JwY1hmaXkzcHdVMDVob24vSncycWJDZUF4U3JXTGRCMGl4L2loUkQyZmlKelJ2L21vZnVHT3p1eFBwR1JyTjh5dCttWFExREVQaWw3V29Xbm5qNFZtSFJyakdUbEF0RnBqZFdsd1NCMGFOQ21PZHhhNGUxcWMzRmw5c2pWM2EwQ3dKeTFEOUVjcWhTZE1RUWNiRjZMWGFVdjlMYll1bUlwYlJrN0FRc2s2eTloOHBPOEE1THN0RmR3VWlBdWllVkY0YlpucWxpK0ttdnVUMDJQRjVFVXQ0ZWhENE0xR2t6Y3d2VUlLKzNiUjg3dFhmQ2M0TXo5d1RJSUJEcU8wUGhEQjY4RkpIUDZlWlJqSXN5VHN3V1ZQSDg4MFpHYlhyK1MxNk5FNE5JSEl4M3FzTmplMXhoSTBCUFVlbFFuQS9VZC9sSDBjblVrVEg5ZDgrR002eXZuSStsdXVDVzBudVB5QzhES0hYTS9SZXROdW5TMlQ1UE5WTnpac2FVaUZUbThFS3FPRHNHakZoczYzZmVOWmtLaUt1T2JOMnhtNnBZekU5QVROMExQVktOT2lFVHpiYWNSc1FMTFFFWHlGU28ydkoyV0JxVkovaGFIb3Vpd2txeHdWOUFQTHFvYmwxVGJITTUyK21zOWhZcHM0bjZhVHpyZkJWSVdIOGxobUwxQU9rejRTeldjVW5yM0J4a1NhRTFseW9zZy9TbVB4M2g4SGw3ZFRLUnh0MXpISGdvV3l4ckVzR21WbjNmZ2p6NTJqaWZ5bldETTZUYzFQa240NzllYnZxd2psTUZjdlNZNzM2TWc2NE1VM3NLSEV0a0FZKzNDdGtlcm1STGprSXRlOUs3NlJzTzFkcm9IUlJ0OHhYZTlFQmFZR1IxWDUzOXFpVTh0ZnV6SjBXQXhCY3dwQ2RhclpUaXM3VjRnOTlUN0NhY2o3Z0RDOEwvQVpTdEJOZ1dFdFdnTytPTkRrK3JLeEFrYW9FOTAxU1Zzd2NxdVQ0dHR3ZXpEWmNJVVdWcjlLUWllenoxWWt6cC81TytPZ0J5cmVTLzZrUy9ibndDWlFDU2ozRWthV0syVCtTL2JTL3NJRWlmOWtpclBORUNPZ2JpM3F0YnpxMXMzS1ZLV2ZhMHJUY09nbHkzdUJMU0VRcG9pWlJ6SEdMZ2Z5N2tyVWFQcTlydDByMzEwSlEwUjJsaGxrUHlPQ1F2RXhEOW5lSjV3a25XNWlZMUFyR3FRVkxCdzkyc2hmK0NKV0FPK0RndllUNm9yQVF5dzBDYnB0a3E5anJRc25TVlpycEZRKzdoc1dFT2pQNnFXejFHWnJvRFdkckF5eUJlbXZHNmRWRTc1dHRHU1JqV1RNK3FEckZVdXlEM2pRcDFiWjZjRzlFSEs0TEdEeDFXTFY5OUp2cGV4VWFLeHNhSmRKQTlzZTdhS3k1MjVkeXA2R3ZObXBURWxIUEZQL1c4aVlCUlNidUZiNWJmYVpMOW4yWmNaQ3NHSzVPQ3BPVnpidFVyN0I3R1hCNlJ1d05wcldnck5SeUgreU14THFvdXJDczM0ODFoZXRZVmRUOTRkVnA2OW4xRTBtSVJSTU0xTXIyelByVHJMVUd3eDVkMjM1V2U2Vng3Ymt4SXl3clN2eGZQZzR6RWZ4eHdQc3JFT0M1M0pHMjJMU1JzamZoZnAvQ0xMOVdrUUt6bWYzZHRCZEZLNmk1WkIrNmtiVlNPYkZGSU80TFNHeWZwdEhJTFB4dlduMXk0TkVaY3pFOEZLNmllMHJPVisxdUFQY2FsbUdER2QrSVR4NnZnVTFZUlltcmdqc2pmY3crdFpWYnB1NFFGN1hhTlNWb0R0ZHJ6SWdycGVmanJDL0RJQnpQWGxMNFRya3V1OFFTdHRGMEx5ZU8yNEprQ1Fmdy9DbEtGUFhWUnV4V3BMVVk2WldKTkJCbDlQaWVqdi9EdUJ2NnRremNmL05sb01jeGtpYTZiTTZ0TEQ1WmNjcGJ0aC85T2NHSWJRUllETmdSM05SWndxamhwUVR0MlQ1aFh1ZTBJMWF4V2NwTlJDVmViajRaRmNvSGI3YVJKUEs3WXN6QTRHMEN5VmRPNDJkUVVnd0g1aGVKam0wbVlhZkJiU1dxeUJKZzdBOWFkRGR3ZXZqT05RMjRZMDRCY1V5RnBVb0pNTFNrN01vd2lrc3M1bWlGWDBjUmFDWThlbVZvQ2tMZERGSW5CcHRmd3paQjA4cmI0QUdWcEJkSkVLcmd4ZldBTkROYmI4WnZLTVE0bGZ3ZHVQSWVsZVdzQ29Jb283RmF6UHdQWHVCeHA2U1llc2YrVXRrbUhMTlhnSGl2Tk9lb3RSTWdwV1kzUzl2aVFDUnl4Sk00S2J1aVNiQzliSnk3UkZvOUVMQ2VqZXFITW5pL3RUWEtWTUxIMFlnblZkNjE3QVpoOGlzSHo4SW1kTmdYaXU3WUU3eFBSTkRkQ2N6S0luVXpvWm9OVlV4VGtZcHBuYlRsRUxGU0U0cVVoRVBuYXFUVU5HdFBWcElXZFpIZzZTWURwZ3VYNWF2c01nWWV3ZG9WM0lwUVA2VVBvcUFoQ3pKWGsyQm8yT1RhVTcwK21iSzh4Rjh6YUk5dGJuNmxJMDdRQXBZTWl0WDgzc0V4aW1YK3dTOEpqcG9hOFQ5aDJBMjFGczdreHZRaDdSVlJjS3JZcGY0R3U3OCs2cEtRYXcrendNcGovbDhudmtkMWhiMFJTNDNwN1Y3TjdIUnJkTjZ3dUd1ZmlOVHF0bXNycXZBeHRCM3h1c044R0V4aUt5QVl5eFgyVFMvK0hmb3FKSlhxYTZtL0g5dm5QU1Z4MUVoVXNvdUN3c1FFR3IxQkFDQVRiaEVGdCttUzhxRVo1eEx5WnNZRTBEYk1YWWRUSXErVkF4eDZnaytJcm5lbmdjN0ZVcXhhbzkzV3VDYWFzbGdqSVRZc1o5UGV5Mm9ZbmdrSzd4R2wrcWc5TG5nUmF1VzR2ZXpvVzY1dlc1TWpaajhyOXh4eDVSOHhvUmRDTEtLaUZsbFNFWnA5NUl5dzBxdEFmWmFYR0FvRTlYeFlmWldDS2RPRnI4VytpVUtVUnhGT0pEL0hjNlVkNTZZemp6bVF4N0w1a0laNW9Rc0pzMS9pcUNlZENJUlNNai80c25BSDZCK2svSWd3UnIzVncvc3QzOFJJOEhUekxyYk1sS1Q5OTdEcmdoQnZBYVcrZWN3Q1h2Vm9BYjRzQ1dsY0dpaDRsRDlyTUJMVUxTVzl5MTBpYmFWNWFPb3BrVVBud3FoRitnVjZzaHBvVFNnMjhYUjdMRjhVbXVCWHVTTkZwektUNXBPMGpmeElFRnNNb1VrSk5UeTN3OG44WHVubUhTTU9hakVKS2xVK1BOVndncUdtb3hGL2VSMTRWUmlzRzJYSWFEdXNqOW05d2lKTEh1NzF1S0d3QlVuS2xQekVXWVZFcVBWWDl2ZHBVVEVzL1k0ckdxd0RtOGhSVlUzRlR3cXZNaW11UWliZDVaRW1IWWY4ZDBkOEJNZVQ2Q2ZPQkdrWStMdTBwV0o1UXBkcng2b0Vzc3Q4eHp5REtKQmcyczBFQXFpbFpWeldEeWQrVEE0RC9ta0o4OWdiK2ROSjhtbjl2S2VHaWtnWHo2enQ3akFnbzk2anBtVlpnNTYvRjRBdzBBUERXNFRrSTJXb3pIcUVBTnZFZ0VvV2QwVHA3TkM1NUtZZnFrMVp3TVlyV0dIclJ4b2Y3dHFtNHExUzJjOVJ4Yk13Wm0yUlg2V01UeVQ5U0VMbHAzTHNBekZGV3B4Q3RMT1hHWDRWNDZOTFpPY1ZmSE41ekd2L25JT1ZMc2VGcGl3M0I1aVVzbHZkMkp5TUo2ZEVEWHNRUDlWWTk4c1h5VWwzYzFsVXlFUytVQ056ZmNJUThXb2VkR1RnWnFWMFRZcUYveGtLcE0rMTRaY3kxSys5UkNaNDNIRlZCUjhFUjZqbThMODBVWXJGZGgwUDdITEtsU2U2Z2ozOEd5MFhlaVNMay9SL3JLNUZjVzh3VnVvNjA3VjkvdmM2b09veUhyU2RvaUtyRzNDWFNiWmZEN3ZUTk1vU3dCckJqaGVxOVVtN1dMMzFpUTZlUjZKOWk3QXRRMHhRVEN6ejY2cHVEeXVPa0FBR0lwUXhXVjFNUEEwM0RkckFncXYrRmFKamZrMC9hV3p3ZkdqRnlTY2pyYktKUyt1ekF1MVdjTkw3MWYrVVhyYWZFUC9sY0ZhTkNzRU1UMmV1d0JWcFZleGpLNTlIeGZXMC95SjhNV1FYYmlZR0pOM3FIM2IwNkx5aVFRQWFONFBKUnBnMmlIK1R2b0E3ZGc0b1N2Y0RKOVNaTlpvck9KRTBYV3RWSm8wNGVvWkNoNUZ0K0p5Yzg3WEFFY1luRXovSGNHaGswVU8zNTA2YmgvK0prRDJLTjNDMUw5ZG5xdHJpUUpFdmJnTDd6VHRpemJzZTNqTU5rOEVWRjN1QWQxZWJPTFQ2bm5nNVN6TGNmOVNLa3dYVFBROWJvcGlrTUhWdUZEbjBUdDVkcGtQeUQxQS91M0w4UEpLamw4TStXeUsvVm1aNG9pSlZNWHp4bytZMDJrRTN3bGRWa2hhOEdRbDNFcDdJb2c5Uk1selc3SmtDMUR5a0dLRmUxQ1ljYUJISmp0b1dFUVN6UXJBNExidzRiV2hqVmtSRXNtdFI4VlZQTWZTUmpGaURsOHFzbFYxNVhzbTBnMVl1Zi9tNG00b0Ivckk5WHJHT2hTc1dWb1NKb0pndlE1UmFpSENSN3lGL3lUSWVEV1NXMXlvbGJQS3hZRkxhYS81Y1RlY1MrSitpTEZYZ01nM1pwMktGUDNxSHBEMnN1Tmdxb0FUSlA0cE9JeUdQSlc5b3ZvQnVPUzRhSm0rUzVUbUN0dzN0M3F1Zm9GWGpyWm1BdWp5NGdCYmdRT2g2eFNaNk9RVVViMm9odVB4M3E0dEl2eXl1VE9VaGhQU3d1TytyVDR0eGc4b2RmNUFQYWNNUmFJelROWlhtbHc2WXZnb2Q2cWFEbkRiZkxvNWN3VVBWODNzZkRwU3JFZWVLVkRoME9LbE8rZXI3aVdxUzdWMTJ4eDdNa0hPN2pEbUw2Q28wMWZGR0V4T3BQQUFWc1F1ZkpqOVZSYjhxSkpUbTRGVnFJTGxFMWR6L1hLWWZCNGI3Nk5ueEhia0M1eGRhNDRYRmU5cUhOWXV6V2xvVVBveXEyVnNraVcwVEZFSHpOTCtJWkdsN2ExcTNSUTZ1UnlnM3U0dGE0cWVQbkdNcittMUZTM2xySFVNUG9sRzZKVysxdk9xbUVmM1ZMaGxhUG1LZXh4K1lLejhsRUdzMHNqWlFuRDRjWG8xQzF5YjdEb3JUTk9UcVdMN1JLcFpYQjl6MVlRWHJ2TW1WSThJeDEzL2k2ZE5Ndy9pK0lpRzh0TWJuNkRGTk1NdEdIallndDAyM0pOMVVkVHpwVG15YmptQW9URzlqL2ErUXY4dW5vWS9rT29qb1BJWVh3blJNSWFYT1dzYWl4OEVTdHE3WUdvYU5Nd3JxTzBJdDdyWUxHTXlZQklaZTNHR1BhRUdvc0tjMmtQbjk3WXNxaHB5R01HVkdIeXlidXlDdkd1blphM2pRRVBjc3ovOVA5Zmh3a1FUOGUxOGdMdjFrTVRwdis3MWg5SFQ2NmswZWdoMTA4bncxd1htdFNpSExRbWkvL0EySlV4Z05QWHdxVndpMzA2ZWVBSEcwTmY4dnpqQ2ZqNm5tcUxGbkM1K0dRVVJ1cFZrY1drSEZ5TnkxMWNwYUlIL1VBbUU4cFhQVHVPTUxXdGhLeTVJNEhEK1NmZDZWVkVpa0plcnMzVGIzMXEzMStkdCtDVmpGZ0hVNDMyQzBiOVJwNnVXY3lOMFZ5K1VHR0N2L0RjNW5kRjAyTmtkRUZ2SmZ3RlF0T1gxbWVXZVYyeHFQWGJzL3BlRllHWkpYZjFBQ0FCQWtGaFZsdkxkaDBNcWpyd1ZYeU85dW1wc1RCeWxlb0w2SlZXZlZRd3JsVU10YmVvRXErMW0rZTBDajJhSTNIb3RkelNLL2Y3U3RobEU1ODFyblFvcGN1VFNOcHk4Q0hYVU5iTjNpQWVEWnNnVEJjbk5LL1dOZ1dlVjg0dWN0ZHJydE5lZHFzZFlsRmR3R2YzdkpnTWlwWm0ybVE3M0U3THVmU0pERTRyWlRLV05abTdxb3dGQUJLRUJlUlQ0ZVlLNkFLbjAzbXFsSVgzb1FqanI1NnlLdTc3Mm9DaVhWYTlJUVJpRDN0OEVZeUZyVGQ4eXlLdWdvaUZlS0xDTDBwVkU4TzJ5UHlWSTBZMnI1Z0NLcFpVOVY0Y1ZNKzlkdS9Sem8xcFpoTUZNc0o0VUZaQURwY1Y3VEt5YjZqWWt5VzErUUZ4QXh3WUJLcFNzS0p6Q2dzVFVianRtUzhwa1VVb3pRMUR0NFBnS1k4ak1YL1VUSWRRVC8ydHZIbUdaM0IvdWZIUmdSV2FVMnRxcjFDQUxwREMrUXNiZmZtNHhrd0lmMHBWMFpPNGRUZXR6QlpUTExDbnppUXJ1c3B0ZVZnYnBNcWVOVi9RcXlWT2QzOWsxTW9PdE50amhLQy9yNnB6bUZGRjZNMDRpdHRCaldQQzJLSXk5NmQvWmRoRGJ2NUlXL0diVElyb2M4anhxeVkxV082bXc3SDhsVldPUjlwTEE9PTwveGVuYzpDaXBoZXJWYWx1ZT48L3hlbmM6Q2lwaGVyRGF0YT48L3hlbmM6RW5jcnlwdGVkRGF0YT48eGVuYzpFbmNyeXB0ZWRLZXkgSWQ9Il83ZDFjNThhZDQyM2E3YjQzODE3YmRhZjFlOWRiNGQ0ZiIgeG1sbnM6eGVuYz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxlbmMjIj48eGVuYzpFbmNyeXB0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxlbmMjcnNhLW9hZXAtbWdmMXAiIHhtbG5zOnhlbmM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jIyI+PGRzOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNzaGExIiB4bWxuczpkcz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyIvPjwveGVuYzpFbmNyeXB0aW9uTWV0aG9kPjxkczpLZXlJbmZvIHhtbG5zOmRzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIj48ZHM6WDUwOURhdGE+PGRzOlg1MDlDZXJ0aWZpY2F0ZT5NSUlCN3pDQ0FWZ0NDUURGemJLSXA3YjNNVEFOQmdrcWhraUc5dzBCQVFVRkFEQThNUXN3Q1FZRFZRUUdFd0pWVXpFTE1Ba0dBMVVFCkNBd0NSMEV4RERBS0JnTlZCQW9NQTJadmJ6RVNNQkFHQTFVRUF3d0piRzlqWVd4b2IzTjBNQjRYRFRFek1UQXdNakF3TURnMU1Wb1gKRFRFME1UQXdNakF3TURnMU1Wb3dQREVMTUFrR0ExVUVCaE1DVlZNeEN6QUpCZ05WQkFnTUFrZEJNUXd3Q2dZRFZRUUtEQU5tYjI4eApFakFRQmdOVkJBTU1DV3h2WTJGc2FHOXpkRENCbnpBTkJna3Foa2lHOXcwQkFRRUZBQU9CalFBd2dZa0NnWUVBMVBNSFltaFpqMzA4CmtXTGhaVlQ0dk91bHF4LzlpYm01Qjg2ZlBXd1VLS1EyaTEyTVl0ejA3dHp1a1B5bWlzVERoUWFxeUo4S3FiLzZKamhtZU1uRU9kVHYKU1BtSE84bTFaVnZlSlU2Tm9LUm4vbVAvQkQ3Rlc1MldoYnJVWExTZUhWU0tmV2tOazZTNGhrOU1WOVRzd1R2eVJJS3ZSc3cwWC9nZgpucWtyb0pjQ0F3RUFBVEFOQmdrcWhraUc5dzBCQVFVRkFBT0JnUUNNTWxJTytHTmNHZWtldktna2FrcE1kQXFKZnMyNG1hR2I5MER2ClRMYlJaUkQ3WHZuMU1uVkJCUzloemxYaUZMWU9JblhBQ01XNWdjb1JGZmVUUUxTb3VNTThvNTdoMHVLamZUbXVvV0hMUUxpNmhuRisKY3ZDc0VGaUpaNEFiRitEZ21PNlRhcko4TzA1dDh6dm5Pd0psTkNBU1BaUkgvSm1GOHRYMGhvSHVBUT09PC9kczpYNTA5Q2VydGlmaWNhdGU+PC9kczpYNTA5RGF0YT48L2RzOktleUluZm8+PHhlbmM6Q2lwaGVyRGF0YSB4bWxuczp4ZW5jPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyMiPjx4ZW5jOkNpcGhlclZhbHVlPm9qZlNObDlBTWNIMHd3V25FVjlSNkpHWVVlczNDclFEWTFTMDZ3ZkwrV20zYVQrNDE4aWUxQ25BLzZTU3BQY1Q1c3NsUVJMdkQ5dGlaYWZ0ai9XcGZyMGhITzJWT2k4QXQ5VGRYcmExSWprRkNyL0ZLQys4VkMvL2VGWVNtT0piSFo5TzZFRFBXSDArcm14WEZ5cmlFYXptOHhsb3J4bGdFejFiM1ArZHVkND08L3hlbmM6Q2lwaGVyVmFsdWU+PC94ZW5jOkNpcGhlckRhdGE+PHhlbmM6UmVmZXJlbmNlTGlzdD48eGVuYzpEYXRhUmVmZXJlbmNlIFVSST0iI181OGRhMTBkZThmOGMzMGVlYzU2ZjQxZTg2NDNkMDc3OSIvPjwveGVuYzpSZWZlcmVuY2VMaXN0PjwveGVuYzpFbmNyeXB0ZWRLZXk+PC9zYW1sMjpFbmNyeXB0ZWRBc3NlcnRpb24+PC9zYW1sMnA6UmVzcG9uc2U+`
	test.IDPMetadata = `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="http://www.okta.com/exkppsa1qwuFV4D7z0h7">
<md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
<md:KeyDescriptor use="signing">
<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<ds:X509Data>
<ds:X509Certificate>
MIIDpDCCAoygAwIBAgIGAWW0dDUQMA0GCSqGSIb3DQEBCwUAMIGSMQswCQYDVQQGEwJVUzETMBEG A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU MBIGA1UECwwLU1NPUHJvdmlkZXIxEzARBgNVBAMMCmRldi01MTMzOTQxHDAaBgkqhkiG9w0BCQEW DWluZm9Ab2t0YS5jb20wHhcNMTgwOTA3MTQzMjU5WhcNMjgwOTA3MTQzMzU5WjCBkjELMAkGA1UE BhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNV BAoMBE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRMwEQYDVQQDDApkZXYtNTEzMzk0MRwwGgYJ KoZIhvcNAQkBFg1pbmZvQG9rdGEuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA oggcfiSRJ6PGoI8XHKUYd89/BPMmduzR365yUEKSK6TIOcA/jrnJzxWHT9PsvB4znaoEdg27dmX0 IZ2I0bjSoyvp4BT8ZtsuqpamsJOFDajfzrU/dMLIQCwY0+38F+x/gNNL+BhYb6zmrdvomb7yqI2E JuHMXMS786UY5GfD+/n0gRSvd+DpIW8ZlsZMG/llyxO1ZccuUqzkbiVV4w1y5PMvSBL7BAWsTn9G IckQsyF+fsG0bKlN3JQjHmjFUrT0cnWkAJjGIVmmrp9NUWyc/SI01i6WlwcQsKw4PB7EU3J8BINv 9mCGXpwp5vWXRdRGjTT4BmFm8lY0QXHqXa/2+QIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBypFox /IaTXAKFsRQi6WUG0QiBLCR8eLhSUDF3xkgELkNYDErQKNyVaXrYoHwPoWYpok6MYddMkoo2YuPG W6V4zDa0k0ulbzKlvbbZQpkzIJEj4dr+PaqmtHAe7C7YNkj4jlfJP6QdqMK+rCBVU3kCX2c/ARun Vy/pIuLowXrQUCF0cccePD8jryej+cmm9jjHWmQNfHDMAv/vpGSXV2W3bzNALXxfCoKqU15ii6YQ hXU85OE5qXEY92ab3D67gppte7eNn/G7D7cuAZhkt7wfLsjoCVK4bZOwxqUw6mPoXXFpkTnlSo86 p7wkbeii7Epjm5HcXTPPC7jd7ZOu3Hsr
</ds:X509Certificate>
</ds:X509Data>
</ds:KeyInfo>
</md:KeyDescriptor>
<md:NameIDFormat>
urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified
</md:NameIDFormat>
<md:NameIDFormat>
urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress
</md:NameIDFormat>
<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://dev-513394.oktapreview.com/app/rstudioincdev513394_dev_1/exkppsa1qwuFV4D7z0h7/sso/saml"/>
<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://dev-513394.oktapreview.com/app/rstudioincdev513394_dev_1/exkppsa1qwuFV4D7z0h7/sso/saml"/>
</md:IDPSSODescriptor>
</md:EntityDescriptor>
`
	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("http://localhost:8000/saml/metadata"),
		AcsURL:      mustParseURL("http://localhost:8000/saml/acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal([]byte(test.IDPMetadata), &s.IDPMetadata)
	assert.NoError(t, err)

	req := http.Request{PostForm: url.Values{}}
	req.PostForm.Set("SAMLResponse", SamlResponse)
	assertion, err := s.ParseResponse(&req, []string{"id-953d4cab69ff475c5901d12e585b0bb15a7b85fe"})
	assert.NoError(t, err)

	assert.Equal(t, "testuser@testrsc.com", assertion.Subject.NameID.Value)
	assert.Equal(t, []Attribute{
		{
			Name:       "Username",
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified",
			Values: []AttributeValue{
				{
					Type:  "xs:string",
					Value: "FixedValue",
				},
			},
		},
	}, assertion.AttributeStatements[0].Attributes)
}

func TestSPCanHandlePlaintextResponse(t *testing.T) {
	test := NewServiceProviderTest()
	// An actual response from google
	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05 UTC 2006", "Tue Jan 5 16:55:39 UTC 2016")
		return rv
	}
	Clock = dsig.NewFakeClockAt(TimeNow())
	SamlResponse := "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiIHN0YW5kYWxvbmU9Im5vIj8+PHNhbWwycDpSZXNwb25zZSB4bWxuczpzYW1sMnA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpwcm90b2NvbCIgRGVzdGluYXRpb249Imh0dHBzOi8vMjllZTZkMmUubmdyb2suaW8vc2FtbC9hY3MiIElEPSJfZmMxNDFkYjI4NGViMzA5ODYwNTM1MWJkZTRkOWJlNTkiIEluUmVzcG9uc2VUbz0iaWQtZmQ0MTlhNWFiMDQ3MjY0NTQyN2Y4ZTA3ZDg3YTNhNWRkMGIyZTlhNiIgSXNzdWVJbnN0YW50PSIyMDE2LTAxLTA1VDE2OjU1OjM5LjM0OFoiIFZlcnNpb249IjIuMCI+PHNhbWwyOklzc3VlciB4bWxuczpzYW1sMj0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiI+aHR0cHM6Ly9hY2NvdW50cy5nb29nbGUuY29tL28vc2FtbDI/aWRwaWQ9QzAyZGZsMXIxPC9zYW1sMjpJc3N1ZXI+PGRzOlNpZ25hdHVyZSB4bWxuczpkcz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI+PGRzOlNpZ25lZEluZm8+PGRzOkNhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48ZHM6U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxkc2lnLW1vcmUjcnNhLXNoYTI1NiIvPjxkczpSZWZlcmVuY2UgVVJJPSIjX2ZjMTQxZGIyODRlYjMwOTg2MDUzNTFiZGU0ZDliZTU5Ij48ZHM6VHJhbnNmb3Jtcz48ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI2VudmVsb3BlZC1zaWduYXR1cmUiLz48ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PC9kczpUcmFuc2Zvcm1zPjxkczpEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyNzaGEyNTYiLz48ZHM6RGlnZXN0VmFsdWU+bHRNRUJLRzRZNVNLeERScUxHR2xFSGtPd3hla3dQOStybnA2WEtqdkJxVT08L2RzOkRpZ2VzdFZhbHVlPjwvZHM6UmVmZXJlbmNlPjwvZHM6U2lnbmVkSW5mbz48ZHM6U2lnbmF0dXJlVmFsdWU+SFBVV0pmYTlqdVdiKy9wZ0YrQklsc2pycE40NkE0RUNiT3hNdXhmWEFRUCtrMU5KMG9EdTJKYk1pZHpmclJBRkRHMjZaNjZWQWtkcwpBRmYwVFgzMWxvVjdaU0tGS0lVY0tuaFlXTHFuUTZLbmRydnJLbzF5UUhzUkdUNzJoVjl3SWdqTFRTZm5FV3QvOEMxaERQQi96R0txClhXZ3VvNFFHYlZUeVBoVVh3eEFzRmxBNjFDdkE5Q1pzU2xpeHBaY2pOVjUyQmMydzI5RUNRNStBcHZGWjVqRU1EN1JiQTVpMzdBbmgKUVBCeVYrZXo4ZU9Yc0hvQlhsR0drTjlDR201MFR6djZ3TW12WkdkT2pKWlhvRWZGUTA4UFJwbE9DQWpxSjM3QnhpWitLZWtUaE1KYgorelowcG1yeWR2V3lONEMzNWcycGVueGw2QUtxYnhMaXlJUkVaZz09PC9kczpTaWduYXR1cmVWYWx1ZT48ZHM6S2V5SW5mbz48ZHM6WDUwOURhdGE+PGRzOlg1MDlTdWJqZWN0TmFtZT5TVD1DYWxpZm9ybmlhLEM9VVMsT1U9R29vZ2xlIEZvciBXb3JrLENOPUdvb2dsZSxMPU1vdW50YWluIFZpZXcsTz1Hb29nbGUgSW5jLjwvZHM6WDUwOVN1YmplY3ROYW1lPjxkczpYNTA5Q2VydGlmaWNhdGU+TUlJRGREQ0NBbHlnQXdJQkFnSUdBVklTbElsWU1BMEdDU3FHU0liM0RRRUJDd1VBTUhzeEZEQVNCZ05WQkFvVEMwZHZiMmRzWlNCSgpibU11TVJZd0ZBWURWUVFIRXcxTmIzVnVkR0ZwYmlCV2FXVjNNUTh3RFFZRFZRUURFd1pIYjI5bmJHVXhHREFXQmdOVkJBc1REMGR2CmIyZHNaU0JHYjNJZ1YyOXlhekVMTUFrR0ExVUVCaE1DVlZNeEV6QVJCZ05WQkFnVENrTmhiR2xtYjNKdWFXRXdIaGNOTVRZd01UQTEKTVRZeE56UTVXaGNOTWpFd01UQXpNVFl4TnpRNVdqQjdNUlF3RWdZRFZRUUtFd3RIYjI5bmJHVWdTVzVqTGpFV01CUUdBMVVFQnhNTgpUVzkxYm5SaGFXNGdWbWxsZHpFUE1BMEdBMVVFQXhNR1IyOXZaMnhsTVJnd0ZnWURWUVFMRXc5SGIyOW5iR1VnUm05eUlGZHZjbXN4CkN6QUpCZ05WQkFZVEFsVlRNUk13RVFZRFZRUUlFd3BEWVd4cFptOXlibWxoTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEEKTUlJQkNnS0NBUUVBbVVmTVVQeEhTWS9aWVo4OGZVR0FsaFVQNE5pN3pqNTR2c3JzUERBNFVoUWlSZUVEUnVuTjFxM09Ic1NoUm9uZwpnZDRMdkE4My9lLzNwbS9WNjBSNnZ5TWZqM1ovSUdXWStlWjk3RUpVdmprdHQrVlJvQWkyNm9lWTlaVzZTODV5YXB2QTNpdWhFd0lRCk9jdVBtMU9xUlEweVE0c1VEK1d0TC9RU21sWXZEUDVUSzFkNndoVGlzTnNLU3FlRlpDYi9zOU9YMDFVZXhXMUJ1RE9MZVZ0MHJDVzEKa1JOY0JCTERtZDRobkRQMFNWcTduTGhORllYajJFYTZXc3lSQUl2Y2hhVUd5K0ltYTJva1htOTVZZTlrbjhlMTE4aS81clJleUtDbQpCbHNrTWtOYUE0S1dLdklRbTNEZGpnT05nRWQwSXZLRXh5THdZN2E1L0pJVXZCaGI5UUlEQVFBQk1BMEdDU3FHU0liM0RRRUJDd1VBCkE0SUJBUUFVRExNbkhwemZwNFNoZEJxQ3JlVzQ4ZjhyVTk0cTJxTXdyVStXNkRrT3JHSlRBU1ZHUzlSaWIvTUtBaVJZT21xbGFxRVkKTlA1N3BDckUvblJCNUZWZEUrQWxTeC9mUjNraHNRM3pmLzRkWXMyMVN2R2YrT2FzOTlYRWJXZlYwT21QTVltM0lyU0NPQkVWMzF3aAo0MXFSYzVRTG5SK1h1dE5QYlNCTit0bitnaVJDTEdDQkxlODFvVnc0ZlJHUWJna2Q4N3JmTE95M0c2MzBJNnMvSjVmZUZGVVQ4ZDdoCjltcE9lT3FMQ1ByS3BxK3dJM2FEM2xmNG1YcUtJRE5pSEhSb05sNjdBTlB1L04zZk5VMUhwbFZ0dnJvVnBpTnA4N2ZyZ2RsS1RFY2cKUFVrZmJhWUhRR1A2SVMwbHplQ2VEWDB3YWIzcVJvaDcvakp0NS9CUjhJd2Y8L2RzOlg1MDlDZXJ0aWZpY2F0ZT48L2RzOlg1MDlEYXRhPjwvZHM6S2V5SW5mbz48L2RzOlNpZ25hdHVyZT48c2FtbDJwOlN0YXR1cz48c2FtbDJwOlN0YXR1c0NvZGUgVmFsdWU9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpzdGF0dXM6U3VjY2VzcyIvPjwvc2FtbDJwOlN0YXR1cz48c2FtbDI6QXNzZXJ0aW9uIHhtbG5zOnNhbWwyPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiBJRD0iXzllNzY0OTUyZTZhMjYxZTE5NDA5YTM4MjU1ODEwMzNkIiBJc3N1ZUluc3RhbnQ9IjIwMTYtMDEtMDVUMTY6NTU6MzkuMzQ4WiIgVmVyc2lvbj0iMi4wIj48c2FtbDI6SXNzdWVyPmh0dHBzOi8vYWNjb3VudHMuZ29vZ2xlLmNvbS9vL3NhbWwyP2lkcGlkPUMwMmRmbDFyMTwvc2FtbDI6SXNzdWVyPjxzYW1sMjpTdWJqZWN0PjxzYW1sMjpOYW1lSUQ+cm9zc0BvY3RvbGFicy5pbzwvc2FtbDI6TmFtZUlEPjxzYW1sMjpTdWJqZWN0Q29uZmlybWF0aW9uIE1ldGhvZD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmNtOmJlYXJlciI+PHNhbWwyOlN1YmplY3RDb25maXJtYXRpb25EYXRhIEluUmVzcG9uc2VUbz0iaWQtZmQ0MTlhNWFiMDQ3MjY0NTQyN2Y4ZTA3ZDg3YTNhNWRkMGIyZTlhNiIgTm90T25PckFmdGVyPSIyMDE2LTAxLTA1VDE3OjAwOjM5LjM0OFoiIFJlY2lwaWVudD0iaHR0cHM6Ly8yOWVlNmQyZS5uZ3Jvay5pby9zYW1sL2FjcyIvPjwvc2FtbDI6U3ViamVjdENvbmZpcm1hdGlvbj48L3NhbWwyOlN1YmplY3Q+PHNhbWwyOkNvbmRpdGlvbnMgTm90QmVmb3JlPSIyMDE2LTAxLTA1VDE2OjUwOjM5LjM0OFoiIE5vdE9uT3JBZnRlcj0iMjAxNi0wMS0wNVQxNzowMDozOS4zNDhaIj48c2FtbDI6QXVkaWVuY2VSZXN0cmljdGlvbj48c2FtbDI6QXVkaWVuY2U+aHR0cHM6Ly8yOWVlNmQyZS5uZ3Jvay5pby9zYW1sL21ldGFkYXRhPC9zYW1sMjpBdWRpZW5jZT48L3NhbWwyOkF1ZGllbmNlUmVzdHJpY3Rpb24+PC9zYW1sMjpDb25kaXRpb25zPjxzYW1sMjpBdHRyaWJ1dGVTdGF0ZW1lbnQ+PHNhbWwyOkF0dHJpYnV0ZSBOYW1lPSJwaG9uZSIvPjxzYW1sMjpBdHRyaWJ1dGUgTmFtZT0iYWRkcmVzcyIvPjxzYW1sMjpBdHRyaWJ1dGUgTmFtZT0iam9iVGl0bGUiLz48c2FtbDI6QXR0cmlidXRlIE5hbWU9ImZpcnN0TmFtZSI+PHNhbWwyOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOmFueVR5cGUiPlJvc3M8L3NhbWwyOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDI6QXR0cmlidXRlPjxzYW1sMjpBdHRyaWJ1dGUgTmFtZT0ibGFzdE5hbWUiPjxzYW1sMjpBdHRyaWJ1dGVWYWx1ZSB4bWxuczp4cz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEiIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiIHhzaTp0eXBlPSJ4czphbnlUeXBlIj5LaW5kZXI8L3NhbWwyOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDI6QXR0cmlidXRlPjwvc2FtbDI6QXR0cmlidXRlU3RhdGVtZW50PjxzYW1sMjpBdXRoblN0YXRlbWVudCBBdXRobkluc3RhbnQ9IjIwMTYtMDEtMDVUMTY6NTU6MzguMDAwWiIgU2Vzc2lvbkluZGV4PSJfOWU3NjQ5NTJlNmEyNjFlMTk0MDlhMzgyNTU4MTAzM2QiPjxzYW1sMjpBdXRobkNvbnRleHQ+PHNhbWwyOkF1dGhuQ29udGV4dENsYXNzUmVmPnVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphYzpjbGFzc2VzOnVuc3BlY2lmaWVkPC9zYW1sMjpBdXRobkNvbnRleHRDbGFzc1JlZj48L3NhbWwyOkF1dGhuQ29udGV4dD48L3NhbWwyOkF1dGhuU3RhdGVtZW50Pjwvc2FtbDI6QXNzZXJ0aW9uPjwvc2FtbDJwOlJlc3BvbnNlPg=="
	test.IDPMetadata = `<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://accounts.google.com/o/saml2?idpid=C02dfl1r1" validUntil="2021-01-03T16:17:49.000Z">
  <md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>MIIDdDCCAlygAwIBAgIGAVISlIlYMA0GCSqGSIb3DQEBCwUAMHsxFDASBgNVBAoTC0dvb2dsZSBJ
bmMuMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MQ8wDQYDVQQDEwZHb29nbGUxGDAWBgNVBAsTD0dv
b2dsZSBGb3IgV29yazELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWEwHhcNMTYwMTA1
MTYxNzQ5WhcNMjEwMTAzMTYxNzQ5WjB7MRQwEgYDVQQKEwtHb29nbGUgSW5jLjEWMBQGA1UEBxMN
TW91bnRhaW4gVmlldzEPMA0GA1UEAxMGR29vZ2xlMRgwFgYDVQQLEw9Hb29nbGUgRm9yIFdvcmsx
CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEAmUfMUPxHSY/ZYZ88fUGAlhUP4Ni7zj54vsrsPDA4UhQiReEDRunN1q3OHsShRong
gd4LvA83/e/3pm/V60R6vyMfj3Z/IGWY+eZ97EJUvjktt+VRoAi26oeY9ZW6S85yapvA3iuhEwIQ
OcuPm1OqRQ0yQ4sUD+WtL/QSmlYvDP5TK1d6whTisNsKSqeFZCb/s9OX01UexW1BuDOLeVt0rCW1
kRNcBBLDmd4hnDP0SVq7nLhNFYXj2Ea6WsyRAIvchaUGy+Ima2okXm95Ye9kn8e118i/5rReyKCm
BlskMkNaA4KWKvIQm3DdjgONgEd0IvKExyLwY7a5/JIUvBhb9QIDAQABMA0GCSqGSIb3DQEBCwUA
A4IBAQAUDLMnHpzfp4ShdBqCreW48f8rU94q2qMwrU+W6DkOrGJTASVGS9Rib/MKAiRYOmqlaqEY
NP57pCrE/nRB5FVdE+AlSx/fR3khsQ3zf/4dYs21SvGf+Oas99XEbWfV0OmPMYm3IrSCOBEV31wh
41qRc5QLnR+XutNPbSBN+tn+giRCLGCBLe81oVw4fRGQbgkd87rfLOy3G630I6s/J5feFFUT8d7h
9mpOeOqLCPrKpq+wI3aD3lf4mXqKIDNiHHRoNl67ANPu/N3fNU1HplVtvroVpiNp87frgdlKTEcg
PUkfbaYHQGP6IS0lzeCeDX0wab3qRoh7/jJt5/BR8Iwf</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://accounts.google.com/o/saml2/idp?idpid=C02dfl1r1"/>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://accounts.google.com/o/saml2/idp?idpid=C02dfl1r1"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>`

	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("https://29ee6d2e.ngrok.io/saml/metadata"),
		AcsURL:      mustParseURL("https://29ee6d2e.ngrok.io/saml/acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal([]byte(test.IDPMetadata), &s.IDPMetadata)
	assert.NoError(t, err)

	req := http.Request{PostForm: url.Values{}}
	req.PostForm.Set("SAMLResponse", SamlResponse)
	assertion, err := s.ParseResponse(&req, []string{"id-fd419a5ab0472645427f8e07d87a3a5dd0b2e9a6"})
	assert.NoError(t, err)

	assert.Equal(t, "ross@octolabs.io", assertion.Subject.NameID.Value)
	assert.Equal(t, []Attribute{
		{
			Name:   "phone",
			Values: nil,
		},
		{
			Name:   "address",
			Values: nil,
		},
		{
			Name:   "jobTitle",
			Values: nil,
		},
		{
			Name: "firstName",
			Values: []AttributeValue{
				{
					Type:  "xs:anyType",
					Value: "Ross",
				},
			},
		},
		{
			Name: "lastName",
			Values: []AttributeValue{
				{
					Type:  "xs:anyType",
					Value: "Kinder",
				},
			},
		},
	}, assertion.AttributeStatements[0].Attributes)
}

func TestSPRejectsInjectedComment(t *testing.T) {
	test := NewServiceProviderTest()
	// An actual response from google
	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05 UTC 2006", "Tue Jan 5 16:55:39 UTC 2016")
		return rv
	}
	Clock = dsig.NewFakeClockAt(TimeNow())
	SamlResponse := "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiIHN0YW5kYWxvbmU9Im5vIj8+PHNhbWwycDpSZXNwb25zZSB4bWxuczpzYW1sMnA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpwcm90b2NvbCIgRGVzdGluYXRpb249Imh0dHBzOi8vMjllZTZkMmUubmdyb2suaW8vc2FtbC9hY3MiIElEPSJfZmMxNDFkYjI4NGViMzA5ODYwNTM1MWJkZTRkOWJlNTkiIEluUmVzcG9uc2VUbz0iaWQtZmQ0MTlhNWFiMDQ3MjY0NTQyN2Y4ZTA3ZDg3YTNhNWRkMGIyZTlhNiIgSXNzdWVJbnN0YW50PSIyMDE2LTAxLTA1VDE2OjU1OjM5LjM0OFoiIFZlcnNpb249IjIuMCI+PHNhbWwyOklzc3VlciB4bWxuczpzYW1sMj0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiI+aHR0cHM6Ly9hY2NvdW50cy5nb29nbGUuY29tL28vc2FtbDI/aWRwaWQ9QzAyZGZsMXIxPC9zYW1sMjpJc3N1ZXI+PGRzOlNpZ25hdHVyZSB4bWxuczpkcz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI+PGRzOlNpZ25lZEluZm8+PGRzOkNhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48ZHM6U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxkc2lnLW1vcmUjcnNhLXNoYTI1NiIvPjxkczpSZWZlcmVuY2UgVVJJPSIjX2ZjMTQxZGIyODRlYjMwOTg2MDUzNTFiZGU0ZDliZTU5Ij48ZHM6VHJhbnNmb3Jtcz48ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI2VudmVsb3BlZC1zaWduYXR1cmUiLz48ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PC9kczpUcmFuc2Zvcm1zPjxkczpEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyNzaGEyNTYiLz48ZHM6RGlnZXN0VmFsdWU+bHRNRUJLRzRZNVNLeERScUxHR2xFSGtPd3hla3dQOStybnA2WEtqdkJxVT08L2RzOkRpZ2VzdFZhbHVlPjwvZHM6UmVmZXJlbmNlPjwvZHM6U2lnbmVkSW5mbz48ZHM6U2lnbmF0dXJlVmFsdWU+SFBVV0pmYTlqdVdiKy9wZ0YrQklsc2pycE40NkE0RUNiT3hNdXhmWEFRUCtrMU5KMG9EdTJKYk1pZHpmclJBRkRHMjZaNjZWQWtkcwpBRmYwVFgzMWxvVjdaU0tGS0lVY0tuaFlXTHFuUTZLbmRydnJLbzF5UUhzUkdUNzJoVjl3SWdqTFRTZm5FV3QvOEMxaERQQi96R0txClhXZ3VvNFFHYlZUeVBoVVh3eEFzRmxBNjFDdkE5Q1pzU2xpeHBaY2pOVjUyQmMydzI5RUNRNStBcHZGWjVqRU1EN1JiQTVpMzdBbmgKUVBCeVYrZXo4ZU9Yc0hvQlhsR0drTjlDR201MFR6djZ3TW12WkdkT2pKWlhvRWZGUTA4UFJwbE9DQWpxSjM3QnhpWitLZWtUaE1KYgorelowcG1yeWR2V3lONEMzNWcycGVueGw2QUtxYnhMaXlJUkVaZz09PC9kczpTaWduYXR1cmVWYWx1ZT48ZHM6S2V5SW5mbz48ZHM6WDUwOURhdGE+PGRzOlg1MDlTdWJqZWN0TmFtZT5TVD1DYWxpZm9ybmlhLEM9VVMsT1U9R29vZ2xlIEZvciBXb3JrLENOPUdvb2dsZSxMPU1vdW50YWluIFZpZXcsTz1Hb29nbGUgSW5jLjwvZHM6WDUwOVN1YmplY3ROYW1lPjxkczpYNTA5Q2VydGlmaWNhdGU+TUlJRGREQ0NBbHlnQXdJQkFnSUdBVklTbElsWU1BMEdDU3FHU0liM0RRRUJDd1VBTUhzeEZEQVNCZ05WQkFvVEMwZHZiMmRzWlNCSgpibU11TVJZd0ZBWURWUVFIRXcxTmIzVnVkR0ZwYmlCV2FXVjNNUTh3RFFZRFZRUURFd1pIYjI5bmJHVXhHREFXQmdOVkJBc1REMGR2CmIyZHNaU0JHYjNJZ1YyOXlhekVMTUFrR0ExVUVCaE1DVlZNeEV6QVJCZ05WQkFnVENrTmhiR2xtYjNKdWFXRXdIaGNOTVRZd01UQTEKTVRZeE56UTVXaGNOTWpFd01UQXpNVFl4TnpRNVdqQjdNUlF3RWdZRFZRUUtFd3RIYjI5bmJHVWdTVzVqTGpFV01CUUdBMVVFQnhNTgpUVzkxYm5SaGFXNGdWbWxsZHpFUE1BMEdBMVVFQXhNR1IyOXZaMnhsTVJnd0ZnWURWUVFMRXc5SGIyOW5iR1VnUm05eUlGZHZjbXN4CkN6QUpCZ05WQkFZVEFsVlRNUk13RVFZRFZRUUlFd3BEWVd4cFptOXlibWxoTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEEKTUlJQkNnS0NBUUVBbVVmTVVQeEhTWS9aWVo4OGZVR0FsaFVQNE5pN3pqNTR2c3JzUERBNFVoUWlSZUVEUnVuTjFxM09Ic1NoUm9uZwpnZDRMdkE4My9lLzNwbS9WNjBSNnZ5TWZqM1ovSUdXWStlWjk3RUpVdmprdHQrVlJvQWkyNm9lWTlaVzZTODV5YXB2QTNpdWhFd0lRCk9jdVBtMU9xUlEweVE0c1VEK1d0TC9RU21sWXZEUDVUSzFkNndoVGlzTnNLU3FlRlpDYi9zOU9YMDFVZXhXMUJ1RE9MZVZ0MHJDVzEKa1JOY0JCTERtZDRobkRQMFNWcTduTGhORllYajJFYTZXc3lSQUl2Y2hhVUd5K0ltYTJva1htOTVZZTlrbjhlMTE4aS81clJleUtDbQpCbHNrTWtOYUE0S1dLdklRbTNEZGpnT05nRWQwSXZLRXh5THdZN2E1L0pJVXZCaGI5UUlEQVFBQk1BMEdDU3FHU0liM0RRRUJDd1VBCkE0SUJBUUFVRExNbkhwemZwNFNoZEJxQ3JlVzQ4ZjhyVTk0cTJxTXdyVStXNkRrT3JHSlRBU1ZHUzlSaWIvTUtBaVJZT21xbGFxRVkKTlA1N3BDckUvblJCNUZWZEUrQWxTeC9mUjNraHNRM3pmLzRkWXMyMVN2R2YrT2FzOTlYRWJXZlYwT21QTVltM0lyU0NPQkVWMzF3aAo0MXFSYzVRTG5SK1h1dE5QYlNCTit0bitnaVJDTEdDQkxlODFvVnc0ZlJHUWJna2Q4N3JmTE95M0c2MzBJNnMvSjVmZUZGVVQ4ZDdoCjltcE9lT3FMQ1ByS3BxK3dJM2FEM2xmNG1YcUtJRE5pSEhSb05sNjdBTlB1L04zZk5VMUhwbFZ0dnJvVnBpTnA4N2ZyZ2RsS1RFY2cKUFVrZmJhWUhRR1A2SVMwbHplQ2VEWDB3YWIzcVJvaDcvakp0NS9CUjhJd2Y8L2RzOlg1MDlDZXJ0aWZpY2F0ZT48L2RzOlg1MDlEYXRhPjwvZHM6S2V5SW5mbz48L2RzOlNpZ25hdHVyZT48c2FtbDJwOlN0YXR1cz48c2FtbDJwOlN0YXR1c0NvZGUgVmFsdWU9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpzdGF0dXM6U3VjY2VzcyIvPjwvc2FtbDJwOlN0YXR1cz48c2FtbDI6QXNzZXJ0aW9uIHhtbG5zOnNhbWwyPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiBJRD0iXzllNzY0OTUyZTZhMjYxZTE5NDA5YTM4MjU1ODEwMzNkIiBJc3N1ZUluc3RhbnQ9IjIwMTYtMDEtMDVUMTY6NTU6MzkuMzQ4WiIgVmVyc2lvbj0iMi4wIj48c2FtbDI6SXNzdWVyPmh0dHBzOi8vYWNjb3VudHMuZ29vZ2xlLmNvbS9vL3NhbWwyP2lkcGlkPUMwMmRmbDFyMTwvc2FtbDI6SXNzdWVyPjxzYW1sMjpTdWJqZWN0PjxzYW1sMjpOYW1lSUQ+cm9zc0BvY3RvbGFicy5pbzwvc2FtbDI6TmFtZUlEPjxzYW1sMjpTdWJqZWN0Q29uZmlybWF0aW9uIE1ldGhvZD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmNtOmJlYXJlciI+PHNhbWwyOlN1YmplY3RDb25maXJtYXRpb25EYXRhIEluUmVzcG9uc2VUbz0iaWQtZmQ0MTlhNWFiMDQ3MjY0NTQyN2Y4ZTA3ZDg3YTNhNWRkMGIyZTlhNiIgTm90T25PckFmdGVyPSIyMDE2LTAxLTA1VDE3OjAwOjM5LjM0OFoiIFJlY2lwaWVudD0iaHR0cHM6Ly8yOWVlNmQyZS5uZ3Jvay5pby9zYW1sL2FjcyIvPjwvc2FtbDI6U3ViamVjdENvbmZpcm1hdGlvbj48L3NhbWwyOlN1YmplY3Q+PHNhbWwyOkNvbmRpdGlvbnMgTm90QmVmb3JlPSIyMDE2LTAxLTA1VDE2OjUwOjM5LjM0OFoiIE5vdE9uT3JBZnRlcj0iMjAxNi0wMS0wNVQxNzowMDozOS4zNDhaIj48c2FtbDI6QXVkaWVuY2VSZXN0cmljdGlvbj48c2FtbDI6QXVkaWVuY2U+aHR0cHM6Ly8yOWVlNmQyZS5uZ3Jvay5pby9zYW1sL21ldGFkYXRhPC9zYW1sMjpBdWRpZW5jZT48L3NhbWwyOkF1ZGllbmNlUmVzdHJpY3Rpb24+PC9zYW1sMjpDb25kaXRpb25zPjxzYW1sMjpBdHRyaWJ1dGVTdGF0ZW1lbnQ+PHNhbWwyOkF0dHJpYnV0ZSBOYW1lPSJwaG9uZSIvPjxzYW1sMjpBdHRyaWJ1dGUgTmFtZT0iYWRkcmVzcyIvPjxzYW1sMjpBdHRyaWJ1dGUgTmFtZT0iam9iVGl0bGUiLz48c2FtbDI6QXR0cmlidXRlIE5hbWU9ImZpcnN0TmFtZSI+PHNhbWwyOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOmFueVR5cGUiPlJvc3M8L3NhbWwyOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDI6QXR0cmlidXRlPjxzYW1sMjpBdHRyaWJ1dGUgTmFtZT0ibGFzdE5hbWUiPjxzYW1sMjpBdHRyaWJ1dGVWYWx1ZSB4bWxuczp4cz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEiIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiIHhzaTp0eXBlPSJ4czphbnlUeXBlIj5LaW5kZXI8L3NhbWwyOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDI6QXR0cmlidXRlPjwvc2FtbDI6QXR0cmlidXRlU3RhdGVtZW50PjxzYW1sMjpBdXRoblN0YXRlbWVudCBBdXRobkluc3RhbnQ9IjIwMTYtMDEtMDVUMTY6NTU6MzguMDAwWiIgU2Vzc2lvbkluZGV4PSJfOWU3NjQ5NTJlNmEyNjFlMTk0MDlhMzgyNTU4MTAzM2QiPjxzYW1sMjpBdXRobkNvbnRleHQ+PHNhbWwyOkF1dGhuQ29udGV4dENsYXNzUmVmPnVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphYzpjbGFzc2VzOnVuc3BlY2lmaWVkPC9zYW1sMjpBdXRobkNvbnRleHRDbGFzc1JlZj48L3NhbWwyOkF1dGhuQ29udGV4dD48L3NhbWwyOkF1dGhuU3RhdGVtZW50Pjwvc2FtbDI6QXNzZXJ0aW9uPjwvc2FtbDJwOlJlc3BvbnNlPg=="
	test.IDPMetadata = `<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://accounts.google.com/o/saml2?idpid=C02dfl1r1" validUntil="2021-01-03T16:17:49.000Z">
  <md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>MIIDdDCCAlygAwIBAgIGAVISlIlYMA0GCSqGSIb3DQEBCwUAMHsxFDASBgNVBAoTC0dvb2dsZSBJ
bmMuMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MQ8wDQYDVQQDEwZHb29nbGUxGDAWBgNVBAsTD0dv
b2dsZSBGb3IgV29yazELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWEwHhcNMTYwMTA1
MTYxNzQ5WhcNMjEwMTAzMTYxNzQ5WjB7MRQwEgYDVQQKEwtHb29nbGUgSW5jLjEWMBQGA1UEBxMN
TW91bnRhaW4gVmlldzEPMA0GA1UEAxMGR29vZ2xlMRgwFgYDVQQLEw9Hb29nbGUgRm9yIFdvcmsx
CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEAmUfMUPxHSY/ZYZ88fUGAlhUP4Ni7zj54vsrsPDA4UhQiReEDRunN1q3OHsShRong
gd4LvA83/e/3pm/V60R6vyMfj3Z/IGWY+eZ97EJUvjktt+VRoAi26oeY9ZW6S85yapvA3iuhEwIQ
OcuPm1OqRQ0yQ4sUD+WtL/QSmlYvDP5TK1d6whTisNsKSqeFZCb/s9OX01UexW1BuDOLeVt0rCW1
kRNcBBLDmd4hnDP0SVq7nLhNFYXj2Ea6WsyRAIvchaUGy+Ima2okXm95Ye9kn8e118i/5rReyKCm
BlskMkNaA4KWKvIQm3DdjgONgEd0IvKExyLwY7a5/JIUvBhb9QIDAQABMA0GCSqGSIb3DQEBCwUA
A4IBAQAUDLMnHpzfp4ShdBqCreW48f8rU94q2qMwrU+W6DkOrGJTASVGS9Rib/MKAiRYOmqlaqEY
NP57pCrE/nRB5FVdE+AlSx/fR3khsQ3zf/4dYs21SvGf+Oas99XEbWfV0OmPMYm3IrSCOBEV31wh
41qRc5QLnR+XutNPbSBN+tn+giRCLGCBLe81oVw4fRGQbgkd87rfLOy3G630I6s/J5feFFUT8d7h
9mpOeOqLCPrKpq+wI3aD3lf4mXqKIDNiHHRoNl67ANPu/N3fNU1HplVtvroVpiNp87frgdlKTEcg
PUkfbaYHQGP6IS0lzeCeDX0wab3qRoh7/jJt5/BR8Iwf</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://accounts.google.com/o/saml2/idp?idpid=C02dfl1r1"/>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://accounts.google.com/o/saml2/idp?idpid=C02dfl1r1"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>`

	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("https://29ee6d2e.ngrok.io/saml/metadata"),
		AcsURL:      mustParseURL("https://29ee6d2e.ngrok.io/saml/acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal([]byte(test.IDPMetadata), &s.IDPMetadata)
	assert.NoError(t, err)

	// this is a valid response
	{
		req := http.Request{PostForm: url.Values{}}
		req.PostForm.Set("SAMLResponse", SamlResponse)
		assertion, err := s.ParseResponse(&req, []string{"id-fd419a5ab0472645427f8e07d87a3a5dd0b2e9a6"})
		assert.NoError(t, err)
		assert.Equal(t, "ross@octolabs.io", assertion.Subject.NameID.Value)
	}

	// this is a valid response but with a comment injected
	{
		x, _ := base64.StdEncoding.DecodeString(SamlResponse)
		y := strings.Replace(string(x), "ross@octolabs.io", "ross@<!-- and a comment -->octolabs.io", 1)
		SamlResponse = base64.StdEncoding.EncodeToString([]byte(y))

		req := http.Request{PostForm: url.Values{}}
		req.PostForm.Set("SAMLResponse", SamlResponse)
		assertion, err := s.ParseResponse(&req, []string{"id-fd419a5ab0472645427f8e07d87a3a5dd0b2e9a6"})

		// Note: I would expect the injected comment to be stripped and for the signature
		// to validate. Less ideal, but not insecure is the case where the comment breaks
		// the signature, perhaps because xml-c18n isn't being implemented correctly by
		// dsig.
		if err == nil {
			assert.Equal(t,
				"ross@octolabs.io",
				assertion.Subject.NameID.Value)
		}
	}

	// this is an invalid response with a commend injected per CVE-2018-7340
	// ref: https://duo.com/blog/duo-finds-saml-vulnerabilities-affecting-multiple-implementations
	// it *MUST NOT* validate
	{
		x, _ := base64.StdEncoding.DecodeString(SamlResponse)
		y := strings.Replace(string(x), "ross@octolabs.io", "ross@octolabs.io<!-- and a comment -->.example.com", 1)
		SamlResponse = base64.StdEncoding.EncodeToString([]byte(y))

		req := http.Request{PostForm: url.Values{}}
		req.PostForm.Set("SAMLResponse", SamlResponse)
		_, err := s.ParseResponse(&req, []string{"id-fd419a5ab0472645427f8e07d87a3a5dd0b2e9a6"})
		assert.NotNil(t, err)

		realErr := err.(*InvalidResponseError).PrivateErr
		assert.EqualError(t, realErr,
			"cannot validate signature on Response: Signature could not be verified")
	}
}

func TestSPCanParseResponse(t *testing.T) {
	test := NewServiceProviderTest()
	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("https://15661444.ngrok.io/saml2/metadata"),
		AcsURL:      mustParseURL("https://15661444.ngrok.io/saml2/acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal([]byte(test.IDPMetadata), &s.IDPMetadata)
	assert.NoError(t, err)

	req := http.Request{PostForm: url.Values{}}
	req.PostForm.Set("SAMLResponse", base64.StdEncoding.EncodeToString([]byte(test.SamlResponse)))
	assertion, err := s.ParseResponse(&req, []string{"id-9e61753d64e928af5a7a341a97f420c9"})
	assert.NoError(t, err)

	assert.Equal(t, []Attribute{
		{
			FriendlyName: "uid",
			Name:         "urn:oid:0.9.2342.19200300.100.1.1",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []AttributeValue{
				{
					Type:  "xs:string",
					Value: "myself",
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
					Value: "Member",
				},
				{
					Type:  "xs:string",
					Value: "Staff",
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
					Value: "myself@testshib.org",
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
					Value: "And I",
				},
			},
		},
		{
			FriendlyName: "eduPersonScopedAffiliation",
			Name:         "urn:oid:1.3.6.1.4.1.5923.1.1.1.9",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []AttributeValue{
				{
					Type:  "xs:string",
					Value: "Member@testshib.org",
				},
				{
					Type:  "xs:string",
					Value: "Staff@testshib.org",
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
					Value: "Me Myself",
				},
			},
		},
		{
			FriendlyName: "eduPersonEntitlement",
			Name:         "urn:oid:1.3.6.1.4.1.5923.1.1.1.7",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []AttributeValue{
				{
					Type:  "xs:string",
					Value: "urn:mace:dir:entitlement:common-lib-terms",
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
					Value: "Me Myself And I",
				},
			},
		},
		{
			FriendlyName: "eduPersonTargetedID",
			Name:         "urn:oid:1.3.6.1.4.1.5923.1.1.1.10",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []AttributeValue{
				{
					NameID: &NameID{Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", NameQualifier: "https://idp.testshib.org/idp/shibboleth", SPNameQualifier: "https://15661444.ngrok.io/saml2/metadata", Value: "8F+M9ovyaYNwCId0pVkVsnZYRDo="},
				},
			},
		},
		{
			FriendlyName: "telephoneNumber",
			Name:         "urn:oid:2.5.4.20",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []AttributeValue{
				{
					Type:  "xs:string",
					Value: "555-5555",
				},
			},
		},
	}, assertion.AttributeStatements[0].Attributes)
}

func (test *ServiceProviderTest) replaceDestination(newDestination string) {
	newStr := ""
	if newDestination != "" {
		newStr = `Destination="` + newDestination + `"`
	}
	test.SamlResponse = strings.Replace(test.SamlResponse, `Destination="https://15661444.ngrok.io/saml2/acs"`, newStr, 1)
}

func TestSPCanProcessResponseWithoutDestination(t *testing.T) {
	test := NewServiceProviderTest()
	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("https://15661444.ngrok.io/saml2/metadata"),
		AcsURL:      mustParseURL("https://15661444.ngrok.io/saml2/acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal([]byte(test.IDPMetadata), &s.IDPMetadata)
	assert.NoError(t, err)

	req := http.Request{PostForm: url.Values{}}
	test.replaceDestination("")
	req.PostForm.Set("SAMLResponse", base64.StdEncoding.EncodeToString([]byte(test.SamlResponse)))
	_, err = s.ParseResponse(&req, []string{"id-9e61753d64e928af5a7a341a97f420c9"})
	assert.NoError(t, err)
}

func (test *ServiceProviderTest) responseDom() (doc *etree.Document) {
	doc = etree.NewDocument()
	doc.ReadFromString(test.SamlResponse)
	return doc
}

func addSignatureToDocument(doc *etree.Document) *etree.Document {
	responseEl := doc.FindElement("//Response")
	signatureEl := doc.CreateElement("xmldsig:Signature")
	signatureEl.CreateAttr("xmlns:xmldsig", "http://www.w3.org/2000/09/xmldsig#")
	responseEl.AddChild(signatureEl)
	return doc
}

func removeDestinationFromDocument(doc *etree.Document) *etree.Document {
	responseEl := doc.FindElement("//Response")
	responseEl.RemoveAttr("Destination")
	return doc
}

func TestServiceProviderMismatchedDestinationsWithSignaturePresent(t *testing.T) {
	test := NewServiceProviderTest()
	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("https://15661444.ngrok.io/saml2/metadata"),
		AcsURL:      mustParseURL("https://15661444.ngrok.io/saml2/acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal([]byte(test.IDPMetadata), &s.IDPMetadata)
	assert.NoError(t, err)

	req := http.Request{PostForm: url.Values{}}
	s.AcsURL = mustParseURL("https://wrong/saml2/acs")
	bytes, _ := addSignatureToDocument(test.responseDom()).WriteToBytes()
	req.PostForm.Set("SAMLResponse", base64.StdEncoding.EncodeToString(bytes))
	_, err = s.ParseResponse(&req, []string{"id-9e61753d64e928af5a7a341a97f420c9"})
	assert.EqualError(t, err.(*InvalidResponseError).PrivateErr,
		"`Destination` does not match AcsURL (expected \"https://wrong/saml2/acs\", actual \"https://15661444.ngrok.io/saml2/acs\")")
}

func TestServiceProviderMissingDestinationWithSignaturePresent(t *testing.T) {
	test := NewServiceProviderTest()
	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("https://15661444.ngrok.io/saml2/metadata"),
		AcsURL:      mustParseURL("https://15661444.ngrok.io/saml2/acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal([]byte(test.IDPMetadata), &s.IDPMetadata)
	assert.NoError(t, err)

	req := http.Request{PostForm: url.Values{}}
	bytes, _ := removeDestinationFromDocument(addSignatureToDocument(test.responseDom())).WriteToBytes()
	req.PostForm.Set("SAMLResponse", base64.StdEncoding.EncodeToString(bytes))
	_, err = s.ParseResponse(&req, []string{"id-9e61753d64e928af5a7a341a97f420c9"})
	assert.EqualError(t, err.(*InvalidResponseError).PrivateErr,
		"`Destination` does not match AcsURL (expected \"https://15661444.ngrok.io/saml2/acs\", actual \"\")")
}

func TestSPMismatchedDestinationsWithSignaturePresent(t *testing.T) {
	test := NewServiceProviderTest()
	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("https://15661444.ngrok.io/saml2/metadata"),
		AcsURL:      mustParseURL("https://15661444.ngrok.io/saml2/acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal([]byte(test.IDPMetadata), &s.IDPMetadata)
	assert.NoError(t, err)

	req := http.Request{PostForm: url.Values{}}
	test.replaceDestination("https://wrong/saml2/acs")
	bytes, _ := addSignatureToDocument(test.responseDom()).WriteToBytes()
	req.PostForm.Set("SAMLResponse", base64.StdEncoding.EncodeToString(bytes))
	_, err = s.ParseResponse(&req, []string{"id-9e61753d64e928af5a7a341a97f420c9"})
	assert.EqualError(t,
		err.(*InvalidResponseError).PrivateErr,
		"`Destination` does not match AcsURL (expected \"https://15661444.ngrok.io/saml2/acs\", actual \"https://wrong/saml2/acs\")")
}

func TestSPMismatchedDestinationsWithNoSignaturePresent(t *testing.T) {
	test := NewServiceProviderTest()
	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("https://15661444.ngrok.io/saml2/metadata"),
		AcsURL:      mustParseURL("https://15661444.ngrok.io/saml2/acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal([]byte(test.IDPMetadata), &s.IDPMetadata)
	assert.NoError(t, err)

	req := http.Request{PostForm: url.Values{}}
	test.replaceDestination("https://wrong/saml2/acs")
	bytes, _ := test.responseDom().WriteToBytes()
	req.PostForm.Set("SAMLResponse", base64.StdEncoding.EncodeToString(bytes))
	_, err = s.ParseResponse(&req, []string{"id-9e61753d64e928af5a7a341a97f420c9"})
	assert.EqualError(t,
		err.(*InvalidResponseError).PrivateErr,
		"`Destination` does not match AcsURL (expected \"https://15661444.ngrok.io/saml2/acs\", actual \"https://wrong/saml2/acs\")")
}

func TestSPMissingDestinationWithSignaturePresent(t *testing.T) {
	test := NewServiceProviderTest()
	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("https://15661444.ngrok.io/saml2/metadata"),
		AcsURL:      mustParseURL("https://15661444.ngrok.io/saml2/acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal([]byte(test.IDPMetadata), &s.IDPMetadata)
	assert.NoError(t, err)

	req := http.Request{PostForm: url.Values{}}
	test.replaceDestination("")
	bytes, _ := addSignatureToDocument(test.responseDom()).WriteToBytes()
	req.PostForm.Set("SAMLResponse", base64.StdEncoding.EncodeToString(bytes))
	_, err = s.ParseResponse(&req, []string{"id-9e61753d64e928af5a7a341a97f420c9"})
	assert.EqualError(t,
		err.(*InvalidResponseError).PrivateErr,
		"`Destination` does not match AcsURL (expected \"https://15661444.ngrok.io/saml2/acs\", actual \"\")")
}

func TestSPInvalidResponses(t *testing.T) {
	test := NewServiceProviderTest()
	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("https://15661444.ngrok.io/saml2/metadata"),
		AcsURL:      mustParseURL("https://15661444.ngrok.io/saml2/acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal([]byte(test.IDPMetadata), &s.IDPMetadata)
	assert.NoError(t, err)

	req := http.Request{PostForm: url.Values{}}
	req.PostForm.Set("SAMLResponse", "???")
	_, err = s.ParseResponse(&req, []string{"id-9e61753d64e928af5a7a341a97f420c9"})
	assert.EqualError(t,
		err.(*InvalidResponseError).PrivateErr,
		"cannot parse base64: illegal base64 data at input byte 0")

	req.PostForm.Set("SAMLResponse", base64.StdEncoding.EncodeToString([]byte("<hello>World!</hello>")))
	_, err = s.ParseResponse(&req, []string{"id-9e61753d64e928af5a7a341a97f420c9"})
	assert.EqualError(t,
		err.(*InvalidResponseError).PrivateErr,
		"cannot unmarshal response: expected element type <Response> but have <hello>")

	req.PostForm.Set("SAMLResponse", base64.StdEncoding.EncodeToString([]byte(test.SamlResponse)))
	_, err = s.ParseResponse(&req, []string{"wrongRequestID"})
	assert.EqualError(t,
		err.(*InvalidResponseError).PrivateErr,
		"`InResponseTo` does not match any of the possible request IDs (expected [wrongRequestID])")

	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05 MST 2006", "Mon Nov 30 20:57:09 UTC 2016")
		return rv
	}
	Clock = dsig.NewFakeClockAt(TimeNow())
	req.PostForm.Set("SAMLResponse", base64.StdEncoding.EncodeToString([]byte(test.SamlResponse)))
	_, err = s.ParseResponse(&req, []string{"id-9e61753d64e928af5a7a341a97f420c9"})
	assert.EqualError(t,
		err.(*InvalidResponseError).PrivateErr,
		"response IssueInstant expired at 2015-12-01 01:57:51.375 +0000 UTC")
	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05 MST 2006", "Mon Dec 1 01:57:09 UTC 2015")
		return rv
	}
	Clock = dsig.NewFakeClockAt(TimeNow())

	s.IDPMetadata.EntityID = "http://snakeoil.com"
	req.PostForm.Set("SAMLResponse", base64.StdEncoding.EncodeToString([]byte(test.SamlResponse)))
	_, err = s.ParseResponse(&req, []string{"id-9e61753d64e928af5a7a341a97f420c9"})
	assert.EqualError(t,
		err.(*InvalidResponseError).PrivateErr,
		"response Issuer does not match the IDP metadata (expected \"http://snakeoil.com\")")
	s.IDPMetadata.EntityID = "https://idp.testshib.org/idp/shibboleth"

	oldSpStatusSuccess := StatusSuccess
	StatusSuccess = "not:the:success:value"
	req.PostForm.Set("SAMLResponse", base64.StdEncoding.EncodeToString([]byte(test.SamlResponse)))
	_, err = s.ParseResponse(&req, []string{"id-9e61753d64e928af5a7a341a97f420c9"})
	assert.EqualError(t,
		err.(*InvalidResponseError).PrivateErr,
		"urn:oasis:names:tc:SAML:2.0:status:Success")
	StatusSuccess = oldSpStatusSuccess

	s.IDPMetadata.IDPSSODescriptors[0].KeyDescriptors[0].KeyInfo.Certificate = "invalid"
	req.PostForm.Set("SAMLResponse", base64.StdEncoding.EncodeToString([]byte(test.SamlResponse)))
	_, err = s.ParseResponse(&req, []string{"id-9e61753d64e928af5a7a341a97f420c9"})
	assert.EqualError(t,
		err.(*InvalidResponseError).PrivateErr,
		"cannot validate signature on Response: cannot parse certificate: illegal base64 data at input byte 4")

	s.IDPMetadata.IDPSSODescriptors[0].KeyDescriptors[0].KeyInfo.Certificate = "aW52YWxpZA=="
	req.PostForm.Set("SAMLResponse", base64.StdEncoding.EncodeToString([]byte(test.SamlResponse)))
	_, err = s.ParseResponse(&req, []string{"id-9e61753d64e928af5a7a341a97f420c9"})

	assert.EqualError(t,
		err.(*InvalidResponseError).PrivateErr,
		"cannot validate signature on Response: asn1: structure error: tags don't match (16 vs {class:1 tag:9 length:110 isCompound:true}) {optional:false explicit:false application:false private:false defaultValue:<nil> tag:<nil> stringType:0 timeType:0 set:false omitEmpty:false} certificate @2")
}

func TestSPInvalidAssertions(t *testing.T) {
	test := NewServiceProviderTest()
	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("https://15661444.ngrok.io/saml2/metadata"),
		AcsURL:      mustParseURL("https://15661444.ngrok.io/saml2/acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal([]byte(test.IDPMetadata), &s.IDPMetadata)
	assert.NoError(t, err)

	req := http.Request{PostForm: url.Values{}}
	req.PostForm.Set("SAMLResponse", base64.StdEncoding.EncodeToString([]byte(test.SamlResponse)))
	s.IDPMetadata.IDPSSODescriptors[0].KeyDescriptors[0].KeyInfo.Certificate = "invalid"
	_, err = s.ParseResponse(&req, []string{"id-9e61753d64e928af5a7a341a97f420c9"})
	assertionBuf := []byte(err.(*InvalidResponseError).Response)

	assertion := Assertion{}
	err = xml.Unmarshal(assertionBuf, &assertion)
	assert.NoError(t, err)

	err = s.validateAssertion(&assertion, []string{"id-9e61753d64e928af5a7a341a97f420c9"}, TimeNow().Add(time.Hour))
	assert.EqualError(t, err, "expired on 2015-12-01 01:57:51.375 +0000 UTC")

	assertion.Issuer.Value = "bob"
	err = s.validateAssertion(&assertion, []string{"id-9e61753d64e928af5a7a341a97f420c9"}, TimeNow())
	assert.EqualError(t, err, "issuer is not \"https://idp.testshib.org/idp/shibboleth\"")
	assertion = Assertion{}
	xml.Unmarshal(assertionBuf, &assertion)

	assertion.Subject.NameID.NameQualifier = "bob"
	err = s.validateAssertion(&assertion, []string{"id-9e61753d64e928af5a7a341a97f420c9"}, TimeNow())
	assert.NoError(t, err) // not verified
	assertion = Assertion{}
	xml.Unmarshal(assertionBuf, &assertion)

	assertion.Subject.NameID.SPNameQualifier = "bob"
	err = s.validateAssertion(&assertion, []string{"id-9e61753d64e928af5a7a341a97f420c9"}, TimeNow())
	assert.NoError(t, err) // not verified
	assertion = Assertion{}
	xml.Unmarshal(assertionBuf, &assertion)

	err = s.validateAssertion(&assertion, []string{"any request id"}, TimeNow())
	assert.EqualError(t, err, "assertion SubjectConfirmation one of the possible request IDs ([any request id])")

	assertion.Subject.SubjectConfirmations[0].SubjectConfirmationData.Recipient = "wrong/acs/url"
	err = s.validateAssertion(&assertion, []string{"id-9e61753d64e928af5a7a341a97f420c9"}, TimeNow())
	assert.EqualError(t, err, "assertion SubjectConfirmation Recipient is not https://15661444.ngrok.io/saml2/acs")
	assertion = Assertion{}
	xml.Unmarshal(assertionBuf, &assertion)

	assertion.Subject.SubjectConfirmations[0].SubjectConfirmationData.NotOnOrAfter = TimeNow().Add(-1 * time.Hour)
	err = s.validateAssertion(&assertion, []string{"id-9e61753d64e928af5a7a341a97f420c9"}, TimeNow())
	assert.EqualError(t, err, "assertion SubjectConfirmationData is expired")
	assertion = Assertion{}
	xml.Unmarshal(assertionBuf, &assertion)

	assertion.Conditions.NotBefore = TimeNow().Add(time.Hour)
	err = s.validateAssertion(&assertion, []string{"id-9e61753d64e928af5a7a341a97f420c9"}, TimeNow())
	assert.EqualError(t, err, "assertion Conditions is not yet valid")
	assertion = Assertion{}
	xml.Unmarshal(assertionBuf, &assertion)

	assertion.Conditions.NotOnOrAfter = TimeNow().Add(-1 * time.Hour)
	err = s.validateAssertion(&assertion, []string{"id-9e61753d64e928af5a7a341a97f420c9"}, TimeNow())
	assert.EqualError(t, err, "assertion Conditions is expired")
	assertion = Assertion{}
	xml.Unmarshal(assertionBuf, &assertion)

	assertion.Conditions.AudienceRestrictions[0].Audience.Value = "not/our/metadata/url"
	err = s.validateAssertion(&assertion, []string{"id-9e61753d64e928af5a7a341a97f420c9"}, TimeNow())
	assert.EqualError(t, err, "assertion Conditions AudienceRestriction does not contain \"https://15661444.ngrok.io/saml2/metadata\"")
	assertion = Assertion{}
	xml.Unmarshal(assertionBuf, &assertion)

	// Not having an audience is not an error
	assertion.Conditions.AudienceRestrictions = []AudienceRestriction{}
	err = s.validateAssertion(&assertion, []string{"id-9e61753d64e928af5a7a341a97f420c9"}, TimeNow())
	assert.NoError(t, err)
}

func TestSPRealWorldKeyInfoHasRSAPublicKeyNotX509Cert(t *testing.T) {
	// This is a real world SAML response that we observed. It contains <ds:RSAKeyValue> elements
	idpMetadata := `<?xml version="1.0" encoding="UTF-8"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.secureworks.com/SAML2"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>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</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.secureworks.com/SAML2/SSO/POST"/></md:IDPSSODescriptor></md:EntityDescriptor>`
	respStr := `<?xml version="1.0" encoding="UTF-8"?><saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Destination="https://preview.docrocket-ross.test.octolabs.io/saml/acs" ID="28338c8c-39ab-4b94-bcdc-46f68f99d962" InResponseTo="id-3992f74e652d89c3cf1efd6c7e472abaac9bc917" IssueInstant="2017-04-21T13:12:50.830Z" Version="2.0"><saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.secureworks.com/SAML2</saml2:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#28338c8c-39ab-4b94-bcdc-46f68f99d962"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>/6iPSzUnncXDbwrXiqZZVSaHt/Q=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>hpJLvXp7DN5qhYkR0+TfvzAHDTIEmOnjA7QGKxbuqUcLxL+xpLqEiPiyCT3DZ5r4eoUlGSTS4tZ2c/A3wnvzEy+f0Pf5D2dUWCL5RfVp7Q6cndEpqlXjZ3lhymTA+go/SdY9VQFKOBsS6ElT56Pr/QRtqqRP2JQK6pP96voeYqWT0YKCdrBkYZ6fJGQ32AD+mQ62hiMzOu9PvriNJzw2no7xyK1U0+MBNPzCcJ6yOrGqX8/yVB8d1hL9IjstZRbMaszdJnnGGMN/JoOtcFxg6v+a5EFC63uXAUL/inxvdNreZMGnuPJJ7HnuDe8yY089Xzwisy6dts6YJ/doEPFOJQ==</ds:SignatureValue><ds:KeyInfo><ds:KeyValue><ds:RSAKeyValue><ds:Modulus>zZlTNJ+QcTp2yGH1ECXO3ry4GHhcs1CW3I6GPiPvtO+P6lyWxYdQd2RK/Hk9Kap6qpm/qom0rTwb
FU2I67Y2JdQ3T5QBJjGHbGHU1uMxVWkhJluoa0Lpm381zNCJTZp8PetoB8dnIGua9y1aL75v04CG
TzJ14I9/sW+apTkWj7xVQXutvVKETdn4kAy+L33HpriZjQNlcuAbqQj6OWsN4tGkLvNFZT40jQzp
/8/tOQE6n2+zn3I8hUePwjPQROUmCeK86CkF0yVCPQ/vOTsC00Uaeu/SPOUu5ot+/75NPyE8w5Ry
DgefdDXhYNmeuQtwGtcu/FI66atQMNTDoChXJQ==</ds:Modulus><ds:Exponent>AQAB</ds:Exponent></ds:RSAKeyValue></ds:KeyValue></ds:KeyInfo></ds:Signature><saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/><saml2p:StatusMessage>Authentication success.</saml2p:StatusMessage></saml2p:Status><saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="e5afbcaa-be69-4b41-ac48-2f23538accdb" IssueInstant="2017-04-21T13:12:50.830Z" Version="2.0"><saml2:Issuer>https://idp.secureworks.com/SAML2</saml2:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#e5afbcaa-be69-4b41-ac48-2f23538accdb"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>BMN0lUblP0gYGcw2PCyhwFZzkxY=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>F/2aaOQ3J/S6ULUd+gAuIclVueHEC2UfmtO2eR2oYb/YXub9E22yZe7eQgj2wdhYOvacVXN28QJJJG+K3Njwvi6b7mqf+T8N1YwaJW1fYAm28ayg4dEOTjHnjbRMZ6L+3cZPmPcFyE+edhCHEMnTLSqSvBnSyc1cwGdO9PmfWmt6PzUwf2nr2P5577Yc1FEQ9OtTx7ugWN3iPmjtLeTcpZfIDQX9+gSsh0KT+t61uWaYz+PJhtKnZQFeyr3uIxBTxv4wQ90FnmE4PiDvMksin5CDMfiMwd7pn7rNbk4EVHiDgSMkY6P4h8eWQwiqglOrQSZZr4BJgCoUbcNfZCq/7A==</ds:SignatureValue><ds:KeyInfo><ds:KeyValue><ds:RSAKeyValue><ds:Modulus>zZlTNJ+QcTp2yGH1ECXO3ry4GHhcs1CW3I6GPiPvtO+P6lyWxYdQd2RK/Hk9Kap6qpm/qom0rTwb
FU2I67Y2JdQ3T5QBJjGHbGHU1uMxVWkhJluoa0Lpm381zNCJTZp8PetoB8dnIGua9y1aL75v04CG
TzJ14I9/sW+apTkWj7xVQXutvVKETdn4kAy+L33HpriZjQNlcuAbqQj6OWsN4tGkLvNFZT40jQzp
/8/tOQE6n2+zn3I8hUePwjPQROUmCeK86CkF0yVCPQ/vOTsC00Uaeu/SPOUu5ot+/75NPyE8w5Ry
DgefdDXhYNmeuQtwGtcu/FI66atQMNTDoChXJQ==</ds:Modulus><ds:Exponent>AQAB</ds:Exponent></ds:RSAKeyValue></ds:KeyValue></ds:KeyInfo></ds:Signature><saml2:Subject><saml2:NameID>rkinder@secureworks.com</saml2:NameID><saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml2:SubjectConfirmationData InResponseTo="id-3992f74e652d89c3cf1efd6c7e472abaac9bc917" NotBefore="2017-04-21T13:12:50.830Z" NotOnOrAfter="2017-04-21T13:17:50.830Z" Recipient="https://preview.docrocket-ross.test.octolabs.io/saml/acs"/></saml2:SubjectConfirmation></saml2:Subject><saml2:Conditions NotBefore="2017-04-21T13:12:50.830Z" NotOnOrAfter="2017-04-21T13:17:50.830Z"><saml2:AudienceRestriction><saml2:Audience>https://preview.docrocket-ross.test.octolabs.io/saml/metadata</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions><saml2:AuthnStatement AuthnInstant="2017-04-21T13:12:50.830Z" SessionIndex="undefined"><saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml2:AuthnContextClassRef></saml2:AuthnContext></saml2:AuthnStatement></saml2:Assertion></saml2p:Response>
`
	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05 MST 2006", "Fri Apr 21 13:12:51 UTC 2017")
		return rv
	}
	Clock = dsig.NewFakeClockAt(TimeNow())
	s := ServiceProvider{
		Key:         key2017,
		Certificate: cert2017,
		MetadataURL: mustParseURL("https://preview.docrocket-ross.test.octolabs.io/saml/metadata"),
		AcsURL:      mustParseURL("https://preview.docrocket-ross.test.octolabs.io/saml/acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal([]byte(idpMetadata), &s.IDPMetadata)
	assert.NoError(t, err)

	req := http.Request{PostForm: url.Values{}}
	req.PostForm.Set("SAMLResponse", base64.StdEncoding.EncodeToString([]byte(respStr)))
	_, err = s.ParseResponse(&req, []string{"id-3992f74e652d89c3cf1efd6c7e472abaac9bc917"})
	if err != nil {
		assert.NoError(t, err.(*InvalidResponseError).PrivateErr)
	}
	assert.NoError(t, err)
}

var key2017 = mustParsePrivateKey(`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAnu2wAmonitRkVP/lKO+gDWalAEL4qJ1x6EyxMVb/2Xvdw+dg
2G2c1771Lyfvp4XYBK4TAAo3nGhcM/b3vLhk45GeSi4/yOJhmOo0dNyQT0t68zxg
6lM9WiOGr6uruGJDIwXqkmQE+B26iVyycGDXzyOf+g2Z2bMhpLfdCI05noUZcsq3
f8Vqmxx5rSCrxrjrAqEUVCZbyL4wap1JKLbnlzTllkvkfTimUM2gYS8RLk6zFKNt
nj7b3grzec5egZIQ9+w7hdRM5GWvKKzSn9/do1SCii555OmEP0ajakYdi9qGO6zH
041tnt6BzTt0mggBWOBoxK/5TCp+nGMBTvTXywIDAQABAoIBAGc853TqGD2qsnI0
uFvbLREHeG+vEXAWtoO8Le5rIU/ZkrlLeDGfIp9TQFodiyQ7YZPIsDb6bB2B/UMU
TuGctozNbxGo8W5BAD0hBmpTTLr1wSx4MEyHPfdr1HYRAj+INSxvD22A42l5hk7s
lE1D22yHK8h3RVWRc21YspB3jNJXhYq4qHU8ZIOK+I7wEy8AZYP5kI4ZUC/nXFik
SwMeVN7U6TT+53Q6n08pos5Nupq0+3cAvZgneV2PP2fGCLIi9VU8Oh7N1WQMYzBt
rYQwnWR6e2Mo0uH4eaaBlPW/3t4HXbS1b26RULC+i5MU3ZUy02w76liHGuuKAWOy
6p6CkoECgYEAzpnt/9S+HKknCFwKMkvMxZ7xI3TxyG5gd41NYm+w8hPk3QlXzcva
RqM1p2nacok4t8HEeAotkz8sP28GmcB4Egh33fUdhKQAkFrQ/OncWcRfzrhnrAMa
gaNT/DT1QTOvfmnle3QLnZhgEDk6plgujvPmJ104/4TjIUOqru0DebsCgYEAxO20
Biq5Bjfot8HxQE+Ur1VPEyZkYUQ9Xmx/exyMTBLy2bUMvZq40TMDEgGMzYvbOvgR
d7/1X2SVvl3sl2mlRJ3nfSEO/Blq+EovdOi0liUYo5LT4IGx+uToBlfmTPNrTYBp
P7JqH97DKYdM4eujwYkiPaAHkFYsnJi/jEU9cTECgYAssS3D9uB9ULYp38cw5CbS
5TQiyGx5QC9MDVwdHC4538XVbuz4js2UFEBKC+L+feKwFZGLqh/7x2GqAzl5TyJq
PDy53glZpSSeFZc57tkE7i8Ph+KdWjqEqrFDUK1xQl4HSZ8j2pGcsNavC8I9M7w2
nlo+T7NByxxbGMk2d/0VewKBgQCJvr7qhV2wRNEqH6VxV3jn/2L1QSh7hLDsaDXv
VjOoTqTBtUs5II1f/y+Jm73yVH4/TB9jxMiMNh4r7yS7cDEiwtSWCNajbeAN1k5F
lzQhxcbrO5uqcO2eUhkdvsQfVTDcIBL+c/yZWEbouHQFnr6HdDWYJ2TDCBPiYVGy
ewgUMQKBgQCIgGzau6+hH8z6aWTnozGA4m8sWFq+t+ug4Gq6v3IAxBOQ2NhmQMRQ
L3BkCfCGAx5JckBROqEiAvPLftof0bVJoxBKfslDrhJocEUJwjXUxmD5RRLr7SXU
P4hDC736Y0DH3nzRlUZ2IP4mhqSECOEYAuz2VuJBTCbd0VEzpnxVfg==
-----END RSA PRIVATE KEY-----`).(*rsa.PrivateKey)

var cert2017 = mustParseCertificate(`-----BEGIN CERTIFICATE-----
MIIDRTCCAi2gAwIBAgIJANke+OUVRk19MA0GCSqGSIb3DQEBBQUAMCAxHjAcBgNV
BAMTFW15c2VydmljZS5leGFtcGxlLmNvbTAeFw0xNzA0MTkxOTU2MTNaFw0xODA0
MTkxOTU2MTNaMCAxHjAcBgNVBAMTFW15c2VydmljZS5leGFtcGxlLmNvbTCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ7tsAJqJ4rUZFT/5SjvoA1mpQBC
+KidcehMsTFW/9l73cPnYNhtnNe+9S8n76eF2ASuEwAKN5xoXDP297y4ZOORnkou
P8jiYZjqNHTckE9LevM8YOpTPVojhq+rq7hiQyMF6pJkBPgduolcsnBg188jn/oN
mdmzIaS33QiNOZ6FGXLKt3/Fapscea0gq8a46wKhFFQmW8i+MGqdSSi255c05ZZL
5H04plDNoGEvES5OsxSjbZ4+294K83nOXoGSEPfsO4XUTORlryis0p/f3aNUgoou
eeTphD9Go2pGHYvahjusx9ONbZ7egc07dJoIAVjgaMSv+UwqfpxjAU7018sCAwEA
AaOBgTB/MB0GA1UdDgQWBBSYE9Nwp/eUqfRQ11rqwoowNFHNyTBQBgNVHSMESTBH
gBSYE9Nwp/eUqfRQ11rqwoowNFHNyaEkpCIwIDEeMBwGA1UEAxMVbXlzZXJ2aWNl
LmV4YW1wbGUuY29tggkA2R745RVGTX0wDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0B
AQUFAAOCAQEAVJmpMg1ZpDGweoCU4k66RVDpPzSuPJ+9H9L2jcaA38itDtXmG9Iz
dbOLpNF9fDbU60P421SgS0nF/s7zkxkYJWOoZaced/vUO6H9TdWEZay+uywAjvoZ
GwkZ9HxYMqKMVld4EwW/OwT67UVBdtgkSfI1O7ojqDOFx7U4+HJWxUEwGOc0pOPz
NyLSYCsAkQt2CZU7dN72L96Ka8xxklNaVcUaUH+zOWF1JBamV9s6M2umcdBot8MO
3m1zQTkXzBKM3f+Yvk+dRjO4TSW90h2oQqot8xrkPhy+DgOqJj3/lKmZXjqE5mAE
hpQB0uVPekPvKN89hCnkPo2EvXKPf7VZgg==
-----END CERTIFICATE-----
`)

func TestSPRealWorldAssertionSignedNotResponse(t *testing.T) {
	// This is a real world SAML response that we observed. It contains <ds:RSAKeyValue> elements rather than
	// a certificate in the response.
	idpMetadata := `<?xml version="1.0" encoding="UTF-8"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.secureworks.com/SAML2"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>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</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.secureworks.com/SAML2/SSO/POST"/></md:IDPSSODescriptor></md:EntityDescriptor>`
	respStr := `<?xml version="1.0" encoding="UTF-8"?><saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Destination="https://preview.docrocket-ross.test.octolabs.io/saml/acs" ID="28338c8c-39ab-4b94-bcdc-46f68f99d962" InResponseTo="id-3992f74e652d89c3cf1efd6c7e472abaac9bc917" IssueInstant="2017-04-21T13:12:50.830Z" Version="2.0"><saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.secureworks.com/SAML2</saml2:Issuer><saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/><saml2p:StatusMessage>Authentication success.</saml2p:StatusMessage></saml2p:Status><saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="e5afbcaa-be69-4b41-ac48-2f23538accdb" IssueInstant="2017-04-21T13:12:50.830Z" Version="2.0"><saml2:Issuer>https://idp.secureworks.com/SAML2</saml2:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#e5afbcaa-be69-4b41-ac48-2f23538accdb"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>BMN0lUblP0gYGcw2PCyhwFZzkxY=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>F/2aaOQ3J/S6ULUd+gAuIclVueHEC2UfmtO2eR2oYb/YXub9E22yZe7eQgj2wdhYOvacVXN28QJJJG+K3Njwvi6b7mqf+T8N1YwaJW1fYAm28ayg4dEOTjHnjbRMZ6L+3cZPmPcFyE+edhCHEMnTLSqSvBnSyc1cwGdO9PmfWmt6PzUwf2nr2P5577Yc1FEQ9OtTx7ugWN3iPmjtLeTcpZfIDQX9+gSsh0KT+t61uWaYz+PJhtKnZQFeyr3uIxBTxv4wQ90FnmE4PiDvMksin5CDMfiMwd7pn7rNbk4EVHiDgSMkY6P4h8eWQwiqglOrQSZZr4BJgCoUbcNfZCq/7A==</ds:SignatureValue><ds:KeyInfo><ds:KeyValue><ds:RSAKeyValue><ds:Modulus>zZlTNJ+QcTp2yGH1ECXO3ry4GHhcs1CW3I6GPiPvtO+P6lyWxYdQd2RK/Hk9Kap6qpm/qom0rTwb
FU2I67Y2JdQ3T5QBJjGHbGHU1uMxVWkhJluoa0Lpm381zNCJTZp8PetoB8dnIGua9y1aL75v04CG
TzJ14I9/sW+apTkWj7xVQXutvVKETdn4kAy+L33HpriZjQNlcuAbqQj6OWsN4tGkLvNFZT40jQzp
/8/tOQE6n2+zn3I8hUePwjPQROUmCeK86CkF0yVCPQ/vOTsC00Uaeu/SPOUu5ot+/75NPyE8w5Ry
DgefdDXhYNmeuQtwGtcu/FI66atQMNTDoChXJQ==</ds:Modulus><ds:Exponent>AQAB</ds:Exponent></ds:RSAKeyValue></ds:KeyValue></ds:KeyInfo></ds:Signature><saml2:Subject><saml2:NameID>rkinder@secureworks.com</saml2:NameID><saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml2:SubjectConfirmationData InResponseTo="id-3992f74e652d89c3cf1efd6c7e472abaac9bc917" NotBefore="2017-04-21T13:12:50.830Z" NotOnOrAfter="2017-04-21T13:17:50.830Z" Recipient="https://preview.docrocket-ross.test.octolabs.io/saml/acs"/></saml2:SubjectConfirmation></saml2:Subject><saml2:Conditions NotBefore="2017-04-21T13:12:50.830Z" NotOnOrAfter="2017-04-21T13:17:50.830Z"><saml2:AudienceRestriction><saml2:Audience>https://preview.docrocket-ross.test.octolabs.io/saml/metadata</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions><saml2:AuthnStatement AuthnInstant="2017-04-21T13:12:50.830Z" SessionIndex="undefined"><saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml2:AuthnContextClassRef></saml2:AuthnContext></saml2:AuthnStatement></saml2:Assertion></saml2p:Response>
`
	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05 MST 2006", "Fri Apr 21 13:12:51 UTC 2017")
		return rv
	}
	Clock = dsig.NewFakeClockAt(TimeNow())

	s := ServiceProvider{
		Key:         key2017,
		Certificate: cert2017,
		MetadataURL: mustParseURL("https://preview.docrocket-ross.test.octolabs.io/saml/metadata"),
		AcsURL:      mustParseURL("https://preview.docrocket-ross.test.octolabs.io/saml/acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal([]byte(idpMetadata), &s.IDPMetadata)
	assert.NoError(t, err)

	req := http.Request{PostForm: url.Values{}}
	req.PostForm.Set("SAMLResponse", base64.StdEncoding.EncodeToString([]byte(respStr)))
	_, err = s.ParseResponse(&req, []string{"id-3992f74e652d89c3cf1efd6c7e472abaac9bc917"})
	if err != nil {
		assert.NoError(t, err.(*InvalidResponseError).PrivateErr)
	}
	assert.NoError(t, err)
}

func TestServiceProviderCanHandleSignedAssertionsResponse(t *testing.T) {
	test := NewServiceProviderTest()

	// Note: This test uses an actual response from onelogin, submitted by a user.
	// However, the test data below isn't actually valid -- the issue instant is
	// before the certificate's issued time. In order to preserve this test data and
	// signatures, we assign a different time to Clock, used by xmldsig than to
	// TimeNow which is used to verify the issue time of the SAML assertion.

	Clock = dsig.NewFakeClockAt(func() time.Time {
		rv, _ := time.Parse(timeFormat, "2014-07-17T14:12:57Z")
		return rv
	}())
	TimeNow = func() time.Time {
		rv, _ := time.Parse(timeFormat, "2014-07-17T01:02:59Z")
		return rv
	}

	SamlResponse := `PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIHhtbG5zOnNhbWw9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iIElEPSJfOGU4ZGM1ZjY5YTk4Y2M0YzFmZjM0MjdlNWNlMzQ2MDZmZDY3MmY5MWU2IiBWZXJzaW9uPSIyLjAiIElzc3VlSW5zdGFudD0iMjAxNC0wNy0xN1QwMTowMTo0OFoiIERlc3RpbmF0aW9uPSJodHRwOi8vc3AuZXhhbXBsZS5jb20vZGVtbzEvaW5kZXgucGhwP2FjcyIgSW5SZXNwb25zZVRvPSJPTkVMT0dJTl80ZmVlM2IwNDYzOTVjNGU3NTEwMTFlOTdmODkwMGI1MjczZDU2Njg1Ij4KICA8c2FtbDpJc3N1ZXI+aHR0cDovL2lkcC5leGFtcGxlLmNvbS9tZXRhZGF0YS5waHA8L3NhbWw6SXNzdWVyPgogIDxzYW1scDpTdGF0dXM+CiAgICA8c2FtbHA6U3RhdHVzQ29kZSBWYWx1ZT0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnN0YXR1czpTdWNjZXNzIi8+CiAgPC9zYW1scDpTdGF0dXM+CiAgPHNhbWw6QXNzZXJ0aW9uIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgSUQ9InBmeDA0NjkwMGM1LTA0MjMtMzVjYi0yYWRiLTcyMjgzYmE1ZDhjZCIgVmVyc2lvbj0iMi4wIiBJc3N1ZUluc3RhbnQ9IjIwMTQtMDctMTdUMDE6MDE6NDhaIj4KICAgIDxzYW1sOklzc3Vlcj5odHRwOi8vaWRwLmV4YW1wbGUuY29tL21ldGFkYXRhLnBocDwvc2FtbDpJc3N1ZXI+PGRzOlNpZ25hdHVyZSB4bWxuczpkcz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI+CiAgPGRzOlNpZ25lZEluZm8+PGRzOkNhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz4KICAgIDxkczpTaWduYXR1cmVNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjcnNhLXNoYTEiLz4KICA8ZHM6UmVmZXJlbmNlIFVSST0iI3BmeDA0NjkwMGM1LTA0MjMtMzVjYi0yYWRiLTcyMjgzYmE1ZDhjZCI+PGRzOlRyYW5zZm9ybXM+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIi8+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjwvZHM6VHJhbnNmb3Jtcz48ZHM6RGlnZXN0TWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI3NoYTEiLz48ZHM6RGlnZXN0VmFsdWU+YmV5ZnFIOXMxUys2bDJHQkhiU2xXOFR4SzZFPTwvZHM6RGlnZXN0VmFsdWU+PC9kczpSZWZlcmVuY2U+PC9kczpTaWduZWRJbmZvPjxkczpTaWduYXR1cmVWYWx1ZT5DSkJMY0pVTm91Q0psY3d5YUtTb1RGdHJUYVJOUWJnWHJFUUdKTmZsdjJkakx0M3J0d2krRzZMd3VQZkQrckF5b3lIbXFyUXlTaVJaZ1lNeWN1bk8vNUQ2R2J5ZVhJVjNrc093Y0YrQXlWZGtrblVpcVN3SDcvOXJkdkVhZmtKcDQ3d1pYKzc4dlFGMDZNcjFnNEpsODByTmNEUncxeE9FdW9QN2pDMjVtMVE9PC9kczpTaWduYXR1cmVWYWx1ZT4KPGRzOktleUluZm8+PGRzOlg1MDlEYXRhPjxkczpYNTA5Q2VydGlmaWNhdGU+TUlJQ2FqQ0NBZE9nQXdJQkFnSUJBREFOQmdrcWhraUc5dzBCQVEwRkFEQlNNUXN3Q1FZRFZRUUdFd0oxY3pFVE1CRUdBMVVFQ0F3S1EyRnNhV1p2Y201cFlURVZNQk1HQTFVRUNnd01UMjVsYkc5bmFXNGdTVzVqTVJjd0ZRWURWUVFEREE1emNDNWxlR0Z0Y0d4bExtTnZiVEFlRncweE5EQTNNVGN4TkRFeU5UWmFGdzB4TlRBM01UY3hOREV5TlRaYU1GSXhDekFKQmdOVkJBWVRBblZ6TVJNd0VRWURWUVFJREFwRFlXeHBabTl5Ym1saE1SVXdFd1lEVlFRS0RBeFBibVZzYjJkcGJpQkpibU14RnpBVkJnTlZCQU1NRG5Od0xtVjRZVzF3YkdVdVkyOXRNSUdmTUEwR0NTcUdTSWIzRFFFQkFRVUFBNEdOQURDQmlRS0JnUURaeCtPTjRJVW9JV3hndWtUYjF0T2lYM2JNWXpZUWl3V1BVTk1wK0ZxODJ4b05vZ3NvMmJ5a1pHMHlpSm01bzh6di9zZDZwR291YXlNZ2t4LzJGU09kYzM2VDBqR2JDSHVSU2J0aWEwUEV6TklSdG1WaU1ydDNBZW9XQmlkUlhtWnN4Q05Md2dJVjZkbjJXcHVFNUF6MGJIZ3BablF4VEtGZWswQk1LVS9kOHdJREFRQUJvMUF3VGpBZEJnTlZIUTRFRmdRVUdIeFlxWll5WDdjVHhLVk9EVmdad1NUZENud3dId1lEVlIwakJCZ3dGb0FVR0h4WXFaWXlYN2NUeEtWT0RWZ1p3U1RkQ253d0RBWURWUjBUQkFVd0F3RUIvekFOQmdrcWhraUc5dzBCQVEwRkFBT0JnUUJ5Rk9sK2hNRklDYmQzREpmbnAyUmdkL2RxdHRzWkcvdHloSUxXdkVyYmlvL0RFZTk4bVhwb3doVGtDMDRFTnByT3lYaTdaYlVxaWljRjg5dUFHeXQxb3FnVFVDRDFWc0xhaHFJY21yemd1bU55VHdMR1dvMTdXREFhMS91c0RoZXRXQU1oZ3pGL0NuZjVlazBuSzAwbTBZWkd5YzRMemdEMENST01BU1RXTmc9PTwvZHM6WDUwOUNlcnRpZmljYXRlPjwvZHM6WDUwOURhdGE+PC9kczpLZXlJbmZvPjwvZHM6U2lnbmF0dXJlPgogICAgPHNhbWw6U3ViamVjdD4KICAgICAgPHNhbWw6TmFtZUlEIFNQTmFtZVF1YWxpZmllcj0iaHR0cDovL3NwLmV4YW1wbGUuY29tL2RlbW8xL21ldGFkYXRhLnBocCIgRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6bmFtZWlkLWZvcm1hdDp0cmFuc2llbnQiPl9jZTNkMjk0OGI0Y2YyMDE0NmRlZTBhMGIzZGQ2ZjY5YjZjZjg2ZjYyZDc8L3NhbWw6TmFtZUlEPgogICAgICA8c2FtbDpTdWJqZWN0Q29uZmlybWF0aW9uIE1ldGhvZD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmNtOmJlYXJlciI+CiAgICAgICAgPHNhbWw6U3ViamVjdENvbmZpcm1hdGlvbkRhdGEgTm90T25PckFmdGVyPSIyMDI0LTAxLTE4VDA2OjIxOjQ4WiIgUmVjaXBpZW50PSJodHRwOi8vc3AuZXhhbXBsZS5jb20vZGVtbzEvaW5kZXgucGhwP2FjcyIgSW5SZXNwb25zZVRvPSJPTkVMT0dJTl80ZmVlM2IwNDYzOTVjNGU3NTEwMTFlOTdmODkwMGI1MjczZDU2Njg1Ii8+CiAgICAgIDwvc2FtbDpTdWJqZWN0Q29uZmlybWF0aW9uPgogICAgPC9zYW1sOlN1YmplY3Q+CiAgICA8c2FtbDpDb25kaXRpb25zIE5vdEJlZm9yZT0iMjAxNC0wNy0xN1QwMTowMToxOFoiIE5vdE9uT3JBZnRlcj0iMjAyNC0wMS0xOFQwNjoyMTo0OFoiPgogICAgICA8c2FtbDpBdWRpZW5jZVJlc3RyaWN0aW9uPgogICAgICAgIDxzYW1sOkF1ZGllbmNlPmh0dHA6Ly9zcC5leGFtcGxlLmNvbS9kZW1vMS9tZXRhZGF0YS5waHA8L3NhbWw6QXVkaWVuY2U+CiAgICAgIDwvc2FtbDpBdWRpZW5jZVJlc3RyaWN0aW9uPgogICAgPC9zYW1sOkNvbmRpdGlvbnM+CiAgICA8c2FtbDpBdXRoblN0YXRlbWVudCBBdXRobkluc3RhbnQ9IjIwMTQtMDctMTdUMDE6MDE6NDhaIiBTZXNzaW9uTm90T25PckFmdGVyPSIyMDI0LTA3LTE3VDA5OjAxOjQ4WiIgU2Vzc2lvbkluZGV4PSJfYmU5OTY3YWJkOTA0ZGRjYWUzYzBlYjQxODlhZGJlM2Y3MWUzMjdjZjkzIj4KICAgICAgPHNhbWw6QXV0aG5Db250ZXh0PgogICAgICAgIDxzYW1sOkF1dGhuQ29udGV4dENsYXNzUmVmPnVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphYzpjbGFzc2VzOlBhc3N3b3JkPC9zYW1sOkF1dGhuQ29udGV4dENsYXNzUmVmPgogICAgICA8L3NhbWw6QXV0aG5Db250ZXh0PgogICAgPC9zYW1sOkF1dGhuU3RhdGVtZW50PgogICAgPHNhbWw6QXR0cmlidXRlU3RhdGVtZW50PgogICAgICA8c2FtbDpBdHRyaWJ1dGUgTmFtZT0idWlkIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OmJhc2ljIj4KICAgICAgICA8c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj50ZXN0PC9zYW1sOkF0dHJpYnV0ZVZhbHVlPgogICAgICA8L3NhbWw6QXR0cmlidXRlPgogICAgICA8c2FtbDpBdHRyaWJ1dGUgTmFtZT0ibWFpbCIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDpiYXNpYyI+CiAgICAgICAgPHNhbWw6QXR0cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOnN0cmluZyI+dGVzdEBleGFtcGxlLmNvbTwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT4KICAgICAgPC9zYW1sOkF0dHJpYnV0ZT4KICAgICAgPHNhbWw6QXR0cmlidXRlIE5hbWU9ImVkdVBlcnNvbkFmZmlsaWF0aW9uIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OmJhc2ljIj4KICAgICAgICA8c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj51c2Vyczwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT4KICAgICAgICA8c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj5leGFtcGxlcm9sZTE8L3NhbWw6QXR0cmlidXRlVmFsdWU+CiAgICAgIDwvc2FtbDpBdHRyaWJ1dGU+CiAgICA8L3NhbWw6QXR0cmlidXRlU3RhdGVtZW50PgogIDwvc2FtbDpBc3NlcnRpb24+Cjwvc2FtbHA6UmVzcG9uc2U+`
	test.IDPMetadata = `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="http://idp.example.com/metadata.php">
  <IDPSSODescriptor xmlns:ds="http://www.w3.org/2000/09/xmldsig#" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>MIICajCCAdOgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBSMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lbG9naW4gSW5jMRcwFQYDVQQDDA5zcC5leGFtcGxlLmNvbTAeFw0xNDA3MTcxNDEyNTZaFw0xNTA3MTcxNDEyNTZaMFIxCzAJBgNVBAYTAnVzMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxPbmVsb2dpbiBJbmMxFzAVBgNVBAMMDnNwLmV4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDZx+ON4IUoIWxgukTb1tOiX3bMYzYQiwWPUNMp+Fq82xoNogso2bykZG0yiJm5o8zv/sd6pGouayMgkx/2FSOdc36T0jGbCHuRSbtia0PEzNIRtmViMrt3AeoWBidRXmZsxCNLwgIV6dn2WpuE5Az0bHgpZnQxTKFek0BMKU/d8wIDAQABo1AwTjAdBgNVHQ4EFgQUGHxYqZYyX7cTxKVODVgZwSTdCnwwHwYDVR0jBBgwFoAUGHxYqZYyX7cTxKVODVgZwSTdCnwwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQByFOl+hMFICbd3DJfnp2Rgd/dqttsZG/tyhILWvErbio/DEe98mXpowhTkC04ENprOyXi7ZbUqiicF89uAGyt1oqgTUCD1VsLahqIcmrzgumNyTwLGWo17WDAa1/usDhetWAMhgzF/Cnf5ek0nK00m0YZGyc4LzgD0CROMASTWNg==</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </KeyDescriptor>
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:transient</NameIDFormat>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://app.onelogin.com/trust/saml2/http-post/sso/503983"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://app.onelogin.com/trust/saml2/http-post/sso/503983"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://app.onelogin.com/trust/saml2/soap/sso/503983"/>
  </IDPSSODescriptor>
  <ContactPerson contactType="technical">
    <SurName>Support</SurName>
    <EmailAddress>support@onelogin.com</EmailAddress>
  </ContactPerson>
</EntityDescriptor>
`
	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("http://sp.example.com/demo1/metadata.php"),
		AcsURL:      mustParseURL("http://sp.example.com/demo1/index.php?acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal([]byte(test.IDPMetadata), &s.IDPMetadata)
	assert.NoError(t, err)

	req := http.Request{PostForm: url.Values{}}
	req.PostForm.Set("SAMLResponse", SamlResponse)
	assertion, err := s.ParseResponse(&req, []string{"ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"})
	if err != nil {
		t.Logf("%s", err.(*InvalidResponseError).PrivateErr)
	}
	assert.NoError(t, err)

	assert.Equal(t, "_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7", assertion.Subject.NameID.Value)
	assert.Equal(t, []Attribute{
		{
			Name:       "uid",
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			Values: []AttributeValue{
				{
					Type:  "xs:string",
					Value: "test",
				},
			},
		},
		{
			Name:       "mail",
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			Values: []AttributeValue{
				{
					Type:  "xs:string",
					Value: "test@example.com",
				},
			},
		},
		{
			Name:       "eduPersonAffiliation",
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			Values: []AttributeValue{
				{
					Type:  "xs:string",
					Value: "users",
				},
				{
					Type:  "xs:string",
					Value: "examplerole1",
				},
			},
		},
	}, assertion.AttributeStatements[0].Attributes)
}
