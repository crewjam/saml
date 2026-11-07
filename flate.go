package saml

import (
	"compress/flate"
	"fmt"
	"io"
)

// flateUncompressLimit caps the size of a message inflated from the
// HTTP-Redirect binding. A redirect carries an AuthnRequest, LogoutRequest
// or LogoutResponse in a URL, which in practice inflates to a few kilobytes.
// Every inflated byte is then checked and parsed, and DEFLATE compresses
// repetitive XML about a thousand times, so the cap bounds the work an
// unauthenticated request can cause.
const flateUncompressLimit = 1024 * 1024 // 1 MiB

func newSaferFlateReader(r io.Reader) io.ReadCloser {
	return &saferFlateReader{r: flate.NewReader(r)}
}

type saferFlateReader struct {
	r     io.ReadCloser
	count int
}

// Read reads at most one byte past the limit, and fails if it gets it, so a
// message of exactly flateUncompressLimit bytes is read in full whatever the
// size of p.
func (r *saferFlateReader) Read(p []byte) (n int, err error) {
	if remaining := flateUncompressLimit - r.count; len(p) > remaining+1 {
		p = p[:remaining+1]
	}
	n, err = r.r.Read(p)
	r.count += n
	if r.count > flateUncompressLimit {
		return 0, fmt.Errorf("flate: uncompress limit exceeded (%d bytes)", flateUncompressLimit)
	}
	return n, err
}

func (r *saferFlateReader) Close() error {
	return r.r.Close()
}
