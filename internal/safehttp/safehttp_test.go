package safehttp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestRefusesNonPublicAddresses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("the request reached the loopback server")
	}))
	defer server.Close()

	resp, err := Client(5*time.Second, nil).Get(server.URL)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "not a permitted destination") ||
		!strings.Contains(err.Error(), "give your own *http.Client") {
		t.Fatalf("got %v", err)
	}
}

func TestGuard(t *testing.T) {
	for addr, ok := range map[string]bool{
		"127.0.0.1:443":         false,
		"10.1.2.3:443":          false,
		"192.168.1.1:80":        false,
		"169.254.169.254:80":    false,
		"100.64.1.1:443":        false,
		"[::1]:443":             false,
		"[fdaa::3]:443":         false, // ULA, such as Fly's private network
		"[64:ff9b::a00:1]:443":  false, // NAT64 of 10.0.0.1
		"[2002:a00:1::1]:443":   false, // 6to4 of 10.0.0.1
		"[::ffff:10.0.0.1]:443": false,
		"8.8.8.8:443":           true,
		"8.8.8.8:8443":          true, // any port
		"[2606:4700::1111]:443": true,
	} {
		network := "tcp4"
		if strings.HasPrefix(addr, "[") {
			network = "tcp6"
		}
		if err := control(network, addr, nil); (err == nil) != ok {
			t.Errorf("%s: %v", addr, err)
		}
	}
}

// fakeLookup resolves the names of the tests without DNS.
func fakeLookup(_ context.Context, host string) ([]netip.Addr, error) {
	switch host {
	case "idp.example.com":
		return []netip.Addr{netip.MustParseAddr("93.184.215.14")}, nil
	case "mapped.example.com":
		return []netip.Addr{netip.MustParseAddr("::ffff:93.184.215.14")}, nil
	case "internal.example.com":
		return []netip.Addr{netip.MustParseAddr("10.0.0.7")}, nil
	case "mixed.example.com":
		return []netip.Addr{netip.MustParseAddr("93.184.215.14"), netip.MustParseAddr("169.254.169.254")}, nil
	case "empty.example.com":
		return nil, nil
	}
	return nil, errors.New("no such host")
}

// fakeProxy starts a proxy that answers every request itself, and returns
// a client that sends every request through it, and the URLs it was asked
// for.
func fakeProxy(t *testing.T) (*http.Client, *[]string) {
	var proxied []string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxied = append(proxied, r.URL.String()) // a proxy request carries the absolute URL
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(proxy.Close)
	proxyURL, _ := url.Parse(proxy.URL)
	return &http.Client{Timeout: 5 * time.Second, Transport: newTransport(http.ProxyURL(proxyURL), fakeLookup)}, &proxied
}

// A proxy, which is often on a private address, may be connected to, and
// a request for a public host goes through it.
func TestProxyIsExempt(t *testing.T) {
	c, proxied := fakeProxy(t)
	for _, target := range []string{
		"http://idp.example.com/metadata",
		"http://mapped.example.com/metadata",
		"http://93.184.215.14:8080/metadata",
	} {
		resp, err := c.Get(target)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		_ = resp.Body.Close()
	}
	if want := []string{
		"http://idp.example.com/metadata",
		"http://mapped.example.com/metadata",
		"http://93.184.215.14:8080/metadata",
	}; strings.Join(*proxied, " ") != strings.Join(want, " ") {
		t.Errorf("proxied %q", *proxied)
	}
}

// Through a proxy, the transport dials only the proxy, so the dial check
// never sees the target: a request whose host is, or resolves to, an
// address the guard refuses is refused before it reaches the proxy.
func TestProxiedRequestToNonPublicHostRefused(t *testing.T) {
	c, proxied := fakeProxy(t)
	for _, target := range []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://10.1.2.3/",
		"http://127.0.0.1:8080/",
		"http://[::1]/",
		"http://[::ffff:10.0.0.1]/",
		"http://[fe80::1%25eth0]/",
		"http://internal.example.com/",
		"http://mixed.example.com/", // every address must be public
		"http://empty.example.com/",
		"http://unknown.example.com/", // unresolvable here: refused
		"https://10.1.2.3/",           // CONNECT
	} {
		resp, err := c.Get(target)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if err == nil || !strings.Contains(err.Error(), "give your own *http.Client") {
			t.Errorf("%s: got %v", target, err)
		}
	}
	if len(*proxied) != 0 {
		t.Errorf("proxied %q", *proxied)
	}
}

// A redirect to a non-public host is checked too, since each request of a
// redirect chain chooses its proxy again.
func TestProxiedRedirectToNonPublicHostRefused(t *testing.T) {
	var proxied []string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxied = append(proxied, r.URL.String())
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer proxy.Close()
	proxyURL, _ := url.Parse(proxy.URL)
	c := &http.Client{Timeout: 5 * time.Second, Transport: newTransport(http.ProxyURL(proxyURL), fakeLookup)}
	resp, err := c.Get("http://idp.example.com/metadata")
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "not a permitted destination") {
		t.Fatalf("got %v", err)
	}
	if len(proxied) != 1 {
		t.Errorf("proxied %q", proxied)
	}
}
