package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"code.dny.dev/ssrf"
)

// maxMetadataSize is the largest metadata document the server fetches.
const maxMetadataSize = 2 << 20

// guard is the SSRF protection of every request the server makes on a
// visitor's behalf: fetching metadata URLs, and the SOAP messages of
// artifact resolution and back-channel logout. It is the Control hook of
// the dialer, so it checks the address actually connected to, after DNS
// resolution, on every connection, redirects included: a hostname that
// resolves (or is rebound) to a private address cannot reach the
// machine's private network, the cloud metadata service or localhost.
//
// code.dny.dev/ssrf allows only public unicast addresses: it refuses the
// IANA special-purpose ranges (private, loopback, link-local, CGNAT,
// documentation, multicast, ...) and, for IPv6, anything outside
// 2000::/3 and the transition prefixes that embed an IPv4 address (NAT64,
// 6to4, Teredo).
var guard = ssrf.New(ssrf.WithPorts(80, 443, 8080, 8443))

// newFetchClient returns the HTTP client the server fetches visitors'
// metadata URLs with.
func newFetchClient() *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second, Control: guard.Safe}
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil) //nolint:gosec // G704: s.fetch refuses private addresses
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/samlmetadata+xml, application/xml, text/xml")
	req.Header.Set("User-Agent", "gosaml.dev metadata fetcher")
	resp, err := s.fetch.Do(req) //nolint:gosec // G704: s.fetch refuses private addresses
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
