package saml

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	dsig "github.com/russellhaering/goxmldsig"
)

type queryParam string

const (
	SAMLRequest  queryParam = "SAMLRequest"
	SAMLResponse queryParam = "SAMLResponse"
	SigAlg       queryParam = "SigAlg"
	Signature    queryParam = "Signature"
	RelayState   queryParam = "RelayState"
)

var (
	// ErrInvalidQuerySignature is returned when the query signature is invalid
	ErrInvalidQuerySignature = errors.New("invalid query signature")
	// ErrNoQuerySignature is returned when the query does not contain a signature
	ErrNoQuerySignature = errors.New("query Signature or SigAlg not found")
)

// Sign Query with the SP private key.
// Returns provided query with the SigAlg and Signature parameters added.
func (sp *ServiceProvider) signQuery(reqT queryParam, query, body, relayState string) (string, error) {
	signingContext, err := GetSigningContext(sp)

	// Encode Query as standard demands. query.Encode() is not standard compliant
	toHash := string(reqT) + "=" + url.QueryEscape(body)
	if relayState != "" {
		toHash += "&RelayState=" + url.QueryEscape(relayState)
	}

	toHash += "&SigAlg=" + url.QueryEscape(sp.SignatureMethod)

	if err != nil {
		return "", err
	}

	sig, err := signingContext.SignString(toHash)
	if err != nil {
		return "", err
	}

	query += "&SigAlg=" + url.QueryEscape(sp.SignatureMethod)
	query += "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))

	return query, nil
}

// validateRedirectBindingSignature validation of the signature of the Redirect Binding in query values
// Query is valid if return is nil
// URL encoding could be done uppercase or lowercase and in addition, can be done following RFC 3986 or not.
// Based on that, if an entity sign using a url enconding mechanism that differs the way another entity decode it, will cause Signature validation issues.
// In order to avoid it the RawQuery is used to retrieve the original query parameters.
// Re doing encoding/decoding of the query parameter are failing especially in ADFS Single Logouts.
func (sp *ServiceProvider) validateRedirectBindingSignature(r *http.Request) error {
	rawQuery := r.URL.RawQuery

	// Extract and validate required query params
	sig := getRawQueryParam(rawQuery, string(Signature))
	alg := getRawQueryParam(rawQuery, string(SigAlg))
	if sig == "" || alg == "" {
		return ErrNoQuerySignature
	}

	// Get the IDP public certificates
	certs, err := sp.getIDPSigningCerts()
	if err != nil {
		return err
	}

	// Determine whether we're dealing with a response or request
	var paramType, paramValue string
	if val := getRawQueryParam(rawQuery, string(SAMLResponse)); val != "" {
		paramType, paramValue = string(SAMLResponse), val
	} else if val := getRawQueryParam(rawQuery, string(SAMLRequest)); val != "" {
		paramType, paramValue = string(SAMLRequest), val
	} else {
		return fmt.Errorf("no SAMLResponse or SAMLRequest found in query")
	}

	// Reconstruct the signed payload (already URL-encoded in RawQuery, so no need to encode/escape it again)
	signedData := fmt.Sprintf("%s=%s", paramType, paramValue)
	if relay := getRawQueryParam(rawQuery, string(RelayState)); relay != "" {
		signedData += "&RelayState=" + relay
	}
	signedData += "&SigAlg=" + alg

	// Decode signature from base64, here we have to decode query param value before base64 decoding
	sigBytes, err := base64.StdEncoding.DecodeString(r.URL.Query().Get(string(Signature)))
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	// Determine hashing algorithm
	hashAlg, sigAlg, hashed, err := computeSignatureHash(r.URL.Query().Get(string(SigAlg)), []byte(signedData))
	if err != nil {
		return err
	}

	// Attempt verification with each valid certificate
	for _, cert := range certs {
		if cert.SignatureAlgorithm != sigAlg {
			continue
		}
		pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			continue
		}
		if err := rsa.VerifyPKCS1v15(pubKey, hashAlg, hashed, sigBytes); err == nil {
			return nil // ✅ Signature verified
		}
	}

	return ErrInvalidQuerySignature
}

// computeSignatureHash computes the signature hash for the given algorithm and data.
func computeSignatureHash(alg string, data []byte) (crypto.Hash, x509.SignatureAlgorithm, []byte, error) {
	switch alg {
	case dsig.RSASHA256SignatureMethod:
		h := sha256.Sum256(data)
		return crypto.SHA256, x509.SHA256WithRSA, h[:], nil
	case dsig.RSASHA512SignatureMethod:
		h := sha512.Sum512(data)
		return crypto.SHA512, x509.SHA512WithRSA, h[:], nil
	case dsig.RSASHA1SignatureMethod:
		h := sha1.Sum(data) // #nosec G401
		return crypto.SHA1, x509.SHA1WithRSA, h[:], nil
	default:
		return 0, 0, nil, fmt.Errorf("unsupported signature algorithm: %s", alg)
	}
}
