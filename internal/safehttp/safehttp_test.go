package safehttp

import (
	"net/http"
	"net/http/httptest"
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

// A proxy, which is often on a private address, may be connected to:
// where it connects is its own business.
func TestProxyIsExempt(t *testing.T) {
	var proxied string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxied = r.URL.String() // a proxy request carries the absolute URL
		_, _ = w.Write([]byte("ok"))
	}))
	defer proxy.Close()
	proxyURL, _ := url.Parse(proxy.URL)

	c := &http.Client{Timeout: 5 * time.Second, Transport: newTransport(http.ProxyURL(proxyURL))}
	resp, err := c.Get("http://idp.example.com/metadata")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if proxied != "http://idp.example.com/metadata" {
		t.Errorf("proxied %q", proxied)
	}
}
