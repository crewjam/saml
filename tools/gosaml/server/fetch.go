package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"syscall"
	"time"
)

// maxMetadataSize is the largest metadata document the server fetches.
const maxMetadataSize = 2 << 20

// errForbiddenAddress is returned when a URL resolves to an address the
// server must not reach on a visitor's behalf.
var errForbiddenAddress = errors.New("that address is not on the public internet")

// publicOnly is a net.Dialer Control function that refuses to connect to
// anything but public unicast addresses. It checks the address actually
// dialed, after DNS resolution, so a hostname that resolves to a private
// address (or is rebound to one) cannot reach the server's own network:
// the machine's private network, the cloud metadata service, localhost.
func publicOnly(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return err
	}
	ip := ap.Addr().Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		cgnat.Contains(ip) || benchmarking.Contains(ip) {
		return errForbiddenAddress
	}
	for _, p := range embedsIPv4 {
		if p.Contains(ip) {
			return errForbiddenAddress
		}
	}
	if p := ap.Port(); p != 80 && p != 443 && p != 8080 && p != 8443 {
		return fmt.Errorf("port %d is not allowed", p)
	}
	return nil
}

var (
	cgnat        = netip.MustParsePrefix("100.64.0.0/10")
	benchmarking = netip.MustParsePrefix("198.18.0.0/15")

	// embedsIPv4 are IPv6 transition prefixes whose addresses carry an
	// IPv4 address, which a gateway may forward to: through NAT64, the
	// public-looking 64:ff9b::a00:1 is 10.0.0.1. Metadata has no need of
	// them, so they are refused rather than decoded and checked.
	embedsIPv4 = []netip.Prefix{
		netip.MustParsePrefix("64:ff9b::/96"),   // NAT64, well-known (RFC 6052)
		netip.MustParsePrefix("64:ff9b:1::/48"), // NAT64, local use (RFC 8215)
		netip.MustParsePrefix("2002::/16"),      // 6to4 (RFC 3056)
		netip.MustParsePrefix("2001::/32"),      // Teredo (RFC 4380)
	}
)

// newFetchClient returns the HTTP client the server fetches visitors'
// metadata URLs with.
func newFetchClient() *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second, Control: publicOnly}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			if req.URL.Scheme != "https" && req.URL.Scheme != "http" {
				return errors.New("redirect to a URL that is not http or https")
			}
			return nil
		},
	}
}

// fetchMetadata fetches a metadata document. URLs of this server's own
// instances are answered locally, so that the test IdPs and SPs can be
// connected to each other without the server calling itself.
func (s *Server) fetchMetadata(ctx context.Context, rawURL string) ([]byte, error) {
	if b, ok, err := s.localMetadata(ctx, rawURL); ok {
		return b, err
	}
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, errors.New("the metadata URL must be an http or https URL")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/samlmetadata+xml, application/xml, text/xml")
	req.Header.Set("User-Agent", "gosaml.dev metadata fetcher")
	resp, err := s.fetch.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot fetch the metadata: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // read-only
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cannot fetch the metadata: %s", resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadataSize+1))
	if err != nil {
		return nil, fmt.Errorf("cannot fetch the metadata: %w", err)
	}
	if len(b) > maxMetadataSize {
		return nil, errors.New("the metadata is larger than 2 MiB")
	}
	return b, nil
}
