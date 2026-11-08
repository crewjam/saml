// Package safehttp makes the HTTP transport of the clients the saml
// packages use when the application gives none: one that connects only to
// public addresses, so that a URL taken from metadata, or a metadata URL
// someone else chose, cannot make the server reach services on its own
// network (server-side request forgery).
package safehttp

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"syscall"
	"time"

	"code.dny.dev/ssrf"
)

// guard allows connections only to public unicast addresses: it refuses
// the IANA special-purpose ranges (private, loopback, link-local, CGNAT,
// documentation, multicast, ...), IPv6 outside 2000::/3, and the IPv6
// prefixes that embed an IPv4 address (NAT64, 6to4, Teredo). Any port is
// allowed: what it protects is the network, and IdPs serve metadata and
// SOAP on ports other than 443.
var guard = ssrf.New(ssrf.WithAnyPort())

// control is the net.Dialer Control hook: it checks the address actually
// dialed, after DNS resolution, so a name that resolves, or is rebound, to
// a private address is refused, as is a redirect to one.
func control(network, address string, c syscall.RawConn) error {
	if err := guard.Safe(network, address, c); err != nil {
		return fmt.Errorf("%w (the default HTTP client of package saml connects only to public addresses: "+
			"to reach this one, such as an IdP on your own network, give your own *http.Client)", err)
	}
	return nil
}

// NewTransport returns a transport like http.DefaultTransport whose
// connections are checked by control.
//
// It uses the proxy of the environment (HTTPS_PROXY and so on), as
// http.DefaultTransport does. A connection to the proxy itself is not
// checked, since the proxy may well be on a private address; where the
// proxy then connects is the proxy's to control.
func NewTransport() *http.Transport { return newTransport(http.ProxyFromEnvironment) }

func newTransport(proxy func(*http.Request) (*url.URL, error)) *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = proxy
	guarded := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second, Control: control}
	plain := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	proxies := proxyAddresses(proxy)
	t.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if proxies[address] {
			return plain.DialContext(ctx, network, address)
		}
		return guarded.DialContext(ctx, network, address)
	}
	return t
}

// proxyAddresses returns the host:port of each proxy that proxy chooses,
// as the transport dials them.
func proxyAddresses(proxy func(*http.Request) (*url.URL, error)) map[string]bool {
	out := map[string]bool{}
	for _, target := range []string{"https://example.com/", "http://example.com/"} {
		req, err := http.NewRequest(http.MethodGet, target, nil)
		if err != nil {
			continue
		}
		u, err := proxy(req)
		if err != nil || u == nil {
			continue
		}
		out[hostPort(u)] = true
	}
	return out
}

func hostPort(u *url.URL) string {
	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "https":
			port = "443"
		case "socks5", "socks5h":
			port = "1080"
		default:
			port = "80"
		}
	}
	return net.JoinHostPort(u.Hostname(), port)
}

// transport is shared by the default clients, so that they share
// connections.
var transport = NewTransport()

// Client returns a client with timeout, the shared guarded transport, and
// checkRedirect.
func Client(timeout time.Duration, checkRedirect func(*http.Request, []*http.Request) error) *http.Client {
	return &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: checkRedirect}
}
