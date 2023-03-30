package samlsp

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	b64 "encoding/base64"

	log "github.com/sirupsen/logrus"

	"github.com/andybalholm/brotli"
	"github.com/lorodoes/saml"
)

const defaultSessionCookieName = "token"

var _ SessionProvider = CookieSessionProvider{}

// CookieSessionProvider is an implementation of SessionProvider that stores
// session tokens in an HTTP cookie.
type CookieSessionProvider struct {
	Name     string
	Domain   string
	HTTPOnly bool
	Secure   bool
	SameSite http.SameSite
	MaxAge   time.Duration
	Codec    SessionCodec
}

// CreateSession is called when we have received a valid SAML assertion and
// should create a new session and modify the http response accordingly, e.g. by
// setting a cookie.
func (c CookieSessionProvider) CreateSession(w http.ResponseWriter, r *http.Request, assertion *saml.Assertion) error {
	log.Debugf("Create Session")
	// Cookies should not have the port attached to them so strip it off
	if domain, _, err := net.SplitHostPort(c.Domain); err == nil {
		c.Domain = domain
	}

	log.Debugf("Creating the assertion")
	session, err := c.Codec.New(assertion)
	if err != nil {
		log.Debugf("Error Creating the assertion")
		return err
	}

	log.Debugf("Encoding the Session")
	value, err := c.Codec.Encode(session)
	if err != nil {
		log.Debugf("Error Encoding the Session")
		return err
	}

	b := compressBrotli([]byte(value))

	uEnc := b64.URLEncoding.EncodeToString(b)

	cookie := &http.Cookie{
		Name:     c.Name,
		Domain:   c.Domain,
		Value:    uEnc,
		MaxAge:   int(c.MaxAge.Seconds()),
		HttpOnly: c.HTTPOnly,
		Secure:   c.Secure || r.URL.Scheme == "https",
		SameSite: c.SameSite,
		Path:     "/",
	}

	log.Debugf("Setting the Cookie")
	http.SetCookie(w, cookie)
	log.Debugf("Log Response: %#v", w)
	log.Debugf("Log Cookie: %#v", cookie)
	log.Debugf("Cookie Set")
	return nil
}

// DeleteSession is called to modify the response such that it removed the current
// session, e.g. by deleting a cookie.
func (c CookieSessionProvider) DeleteSession(w http.ResponseWriter, r *http.Request) error {
	log.Debugf("Delete Session")
	// Cookies should not have the port attached to them so strip it off
	if domain, _, err := net.SplitHostPort(c.Domain); err == nil {
		c.Domain = domain
	}

	cookie, err := r.Cookie(c.Name)

	if err == http.ErrNoCookie {
		return nil
	}
	if err != nil {
		return err
	}

	cookie.Value = ""
	cookie.Expires = time.Unix(1, 0) // past time as close to epoch as possible, but not zero time.Time{}
	cookie.Path = "/"
	cookie.Domain = c.Domain
	http.SetCookie(w, cookie)
	log.Debugf("Log Response: %#v", w)
	log.Debugf("Log Cookie: %#v", cookie)
	return nil
}

// GetSession returns the current Session associated with the request, or
// ErrNoSession if there is no valid session.
func (c CookieSessionProvider) GetSession(r *http.Request) (Session, error) {
	log.Debugf("Get Session")
	cookie, err := r.Cookie(c.Name)
	if err == http.ErrNoCookie {
		log.Debugf("Get Session: Error No Session")
		log.Debugf("Get Session: Error No Session: %s", err)
		return nil, ErrNoSession
	} else if err != nil {
		log.Debugf("Get Session: Error")
		return nil, err
	}

	uDec, _ := b64.URLEncoding.DecodeString(cookie.Value)

	d, _ := decompressBrotli(uDec)

	session, err := c.Codec.Decode(d)
	if err != nil {
		log.Debugf("Get Session decode: Error No Session")
		return nil, ErrNoSession
	}
	log.Debugf("Returning the session")
	return session, nil
}

func compressBrotli(data []byte) []byte {
	var b bytes.Buffer
	w := brotli.NewWriterLevel(&b, brotli.BestCompression)
	w.Write(data)
	w.Close()
	return b.Bytes()
}

func decompressBrotli(compressedData []byte) (string, error) {
	reader := brotli.NewReader(bytes.NewReader(compressedData))
	var decompressedData strings.Builder
	_, err := io.Copy(&decompressedData, reader)
	if err != nil {
		return "", err
	}
	return decompressedData.String(), nil
}
