// Package safehttp makes HTTP transports and clients that connect only to
// public addresses, so that a URL taken from a peer's metadata, or a
// metadata URL someone else chose, cannot make the server reach services
// on its own network (server-side request forgery). The saml packages use
// them when the application gives no *http.Client of its own; applications
// can use them for their own requests to such URLs.
package safehttp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
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
		return refused(err)
	}
	return nil
}

// refused wraps err, the reason a destination is refused, with what to do
// about it.
func refused(err error) error {
	return fmt.Errorf("%w (this HTTP client, the default of package saml, connects only to public addresses: "+
		"to reach this one, such as an IdP on your own network, give your own *http.Client)", err)
}

// lookupFunc resolves a host name to its addresses.
type lookupFunc func(ctx context.Context, host string) ([]netip.Addr, error)

func defaultLookup(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// NewTransport returns a transport like http.DefaultTransport whose
// connections are checked by control.
//
// It uses the proxy of the environment (HTTPS_PROXY and so on), as
// http.DefaultTransport does. A connection to the proxy itself is not
// checked, since the proxy may well be on a private address. But through a
// proxy the transport connects only to the proxy, which connects to the
// target for it, so control never sees the target's address. So before a
// request is handed to a proxy, the host of its URL is checked instead: an
// IP address must be public, and a name must resolve, here, to public
// addresses only (see checkProxiedHost). What this cannot cover is the
// proxy's own DNS resolution: a name that resolves to a public address here
// and to a private one at the proxy, such as by DNS rebinding or with a
// split-horizon DNS, still reaches the proxy's network, unless the proxy
// itself refuses private destinations.
func NewTransport() *http.Transport { return newTransport(http.ProxyFromEnvironment, defaultLookup) }

func newTransport(proxy func(*http.Request) (*url.URL, error), lookup lookupFunc) *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = func(req *http.Request) (*url.URL, error) {
		proxyURL, err := proxy(req)
		if err != nil || proxyURL == nil {
			return proxyURL, err
		}
		if err := checkProxiedHost(req.Context(), req.URL.Hostname(), lookup); err != nil {
			return nil, err
		}
		return proxyURL, nil
	}
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

// checkProxiedHost returns an error unless host, the host of a request
// about to be handed to a proxy, is a public address or a name whose every
// address is public, as guard decides. A name that cannot be resolved here
// is refused too, since where the proxy would connect is then unknown.
func checkProxiedHost(ctx context.Context, host string, lookup lookupFunc) error {
	if host == "" {
		return errors.New("the request URL has no host")
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if err := guard.SafeAddr(addr.Unmap()); err != nil {
			return refused(err)
		}
		return nil
	}
	addrs, err := lookup(ctx, host)
	if err != nil {
		return refused(fmt.Errorf("cannot resolve %s to check it before sending the request through the proxy: %w", host, err))
	}
	if len(addrs) == 0 {
		return refused(fmt.Errorf("%s resolves to no address", host))
	}
	for _, addr := range addrs {
		if err := guard.SafeAddr(addr.Unmap()); err != nil {
			return refused(fmt.Errorf("%s resolves to a refused address: %w", host, err))
		}
	}
	return nil
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
