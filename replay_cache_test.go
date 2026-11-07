package saml

import (
	"encoding/xml"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
	"gotest.tools/v3/golden"
)

// memoryReplayCache is an AssertionReplayCache that remembers every ID it is
// given, with the expiry it was given.
type memoryReplayCache map[string]time.Time

func (c memoryReplayCache) Consume(assertionID string, expiresAt time.Time) error {
	if _, seen := c[assertionID]; seen {
		return ErrAssertionReplayed
	}
	c[assertionID] = expiresAt
	return nil
}

type failingReplayCache struct{}

func (failingReplayCache) Consume(string, time.Time) error { return errors.New("store unavailable") }

const oneloginRequestID = "id-d40c15c104b52691eccf0a2a5c8a15595be75423"

// oneloginSP returns a function that parses the signed OneLogin response in
// testdata, at the moment it was issued, with a service provider using cache.
func oneloginSP(t *testing.T, cache AssertionReplayCache) func(requestID string) (*Assertion, error) {
	t.Helper()
	test := NewServiceProviderTest(t)
	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05 UTC 2006", "Tue Jan 5 17:53:12 UTC 2016")
		return rv
	}
	Clock = dsig.NewFakeClockAt(TimeNow())

	sp := &ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("https://29ee6d2e.ngrok.io/saml/metadata"),
		AcsURL:      mustParseURL("https://29ee6d2e.ngrok.io/saml/acs"),
		IDPMetadata: &EntityDescriptor{},
		ReplayCache: cache,
	}
	assert.NilError(t, xml.Unmarshal(golden.Get(t, "TestSPCanHandleOneloginResponse_IDPMetadata"), sp.IDPMetadata))
	response := string(golden.Get(t, "TestSPCanHandleOneloginResponse_response"))

	return func(requestID string) (*Assertion, error) {
		req := http.Request{PostForm: url.Values{"SAMLResponse": {response}}, URL: &sp.AcsURL}
		return sp.ParseResponse(&req, []string{requestID})
	}
}

func replayPrivateErr(t *testing.T, err error) error {
	t.Helper()
	var ire *InvalidResponseError
	assert.Assert(t, errors.As(err, &ire), "got %v", err)
	return ire.PrivateErr
}

// A response is accepted once; the same response again is refused.
func TestParseResponseRefusesReplay(t *testing.T) {
	cache := memoryReplayCache{}
	parse := oneloginSP(t, cache)

	assertion, err := parse(oneloginRequestID)
	assert.NilError(t, err)
	assert.Check(t, is.Len(cache, 1))
	expiresAt, recorded := cache[assertion.ID]
	assert.Check(t, recorded)
	assert.Check(t, is.Equal(acceptableUntil(assertion), expiresAt))

	_, err = parse(oneloginRequestID)
	assert.Check(t, errors.Is(replayPrivateErr(t, err), ErrAssertionReplayed), "got %v", err)
}

// Without a ReplayCache the same response is accepted again, as before.
func TestParseResponseWithoutReplayCacheAcceptsRepeat(t *testing.T) {
	parse := oneloginSP(t, nil)
	_, err := parse(oneloginRequestID)
	assert.NilError(t, err)
	_, err = parse(oneloginRequestID)
	assert.NilError(t, err)
}

// A response refused for any other reason is not recorded.
func TestParseResponseRecordsNothingWhenRefused(t *testing.T) {
	cache := memoryReplayCache{}
	parse := oneloginSP(t, cache)

	_, err := parse("id-of-another-request")
	assert.Check(t, err != nil)
	assert.Check(t, is.Len(cache, 0))
}

// An error from the cache refuses the response.
func TestParseResponseRefusedWhenTheCacheFails(t *testing.T) {
	_, err := oneloginSP(t, failingReplayCache{})(oneloginRequestID)
	assert.Check(t, is.ErrorContains(replayPrivateErr(t, err), "store unavailable"))
}

// An assertion without an ID cannot be checked, so it is refused rather than
// recorded under the empty ID.
func TestConsumeAssertionRequiresID(t *testing.T) {
	cache := memoryReplayCache{}
	sp := ServiceProvider{ReplayCache: cache}
	a := validAssertion(TimeNow())
	a.ID = ""
	assert.Check(t, is.Error(sp.consumeAssertion(a), "assertion has no ID to check for replay"))
	assert.Check(t, is.Len(cache, 0))
}

// The cache is told the last moment the assertion is acceptable: the earliest
// of the issue deadline and each NotOnOrAfter, with the clock skew the
// expiry checks allow. validateAssertion accepts the assertion at that moment
// and refuses it just after.
func TestAcceptableUntil(t *testing.T) {
	now := TimeNow()
	cases := []struct {
		name     string
		edit     func(a *Assertion)
		deadline time.Time
	}{
		{"issue deadline first", func(a *Assertion) {
			a.Conditions.NotOnOrAfter = now.Add(time.Hour)
			a.Subject.SubjectConfirmations[0].SubjectConfirmationData.NotOnOrAfter = now.Add(time.Hour)
		}, now.Add(MaxIssueDelay)},
		{"conditions first", func(a *Assertion) {
			a.Conditions.NotOnOrAfter = now.Add(-150 * time.Second)
		}, now.Add(-150*time.Second + MaxClockSkew)},
		{"confirmation first", func(a *Assertion) {
			a.Subject.SubjectConfirmations[0].SubjectConfirmationData.NotOnOrAfter = now.Add(-150 * time.Second)
		}, now.Add(-150*time.Second + MaxClockSkew)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sp := requiredConditionsSP()
			a := validAssertion(now)
			c.edit(a)
			deadline := acceptableUntil(a)
			assert.Check(t, is.DeepEqual(c.deadline, deadline))

			assert.Check(t, sp.validateAssertion(a, []string{"id-1"}, deadline))
			assert.Check(t, sp.validateAssertion(a, []string{"id-1"}, deadline.Add(time.Nanosecond)) != nil)
		})
	}
}
