package saml

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRelaxedTimeFormat(t *testing.T) {
	rt := time.Date(1981, 02, 03, 14, 15, 16, 17, time.UTC)
	assert.Equal(t, "1981-02-03T14:15:16Z", RelaxedTime(rt).String())

	buf, err := RelaxedTime(rt).MarshalText()
	assert.NoError(t, err)
	assert.Equal(t, "1981-02-03T14:15:16Z", string(buf))

	loc, err := time.LoadLocation("America/New_York")
	assert.NoError(t, err)
	rt = time.Date(1981, 02, 03, 9, 15, 16, 17, loc)

	assert.Equal(t, "1981-02-03T14:15:16Z", RelaxedTime(rt).String())
	buf, err = RelaxedTime(rt).MarshalText()
	assert.NoError(t, err)
	assert.Equal(t, "1981-02-03T14:15:16Z", string(buf))
}

func TestRelaxedTimeParse(t *testing.T) {
	{
		var rt RelaxedTime
		err := rt.UnmarshalText([]byte("1981-02-03T14:15:16Z"))
		assert.NoError(t, err)
		assert.Equal(t, RelaxedTime(time.Date(1981, 02, 03, 14, 15, 16, 0, time.UTC)), rt)
	}

	{
		var rt RelaxedTime
		err := rt.UnmarshalText([]byte("1981-02-03T14:15:16.178901234Z"))
		assert.NoError(t, err)
		assert.Equal(t, RelaxedTime(time.Date(1981, 02, 03, 14, 15, 16, 179000000, time.UTC)), rt)
	}
	{
		var rt RelaxedTime
		err := rt.UnmarshalText([]byte("1981-02-03T14:15:16.1717Z"))
		assert.NoError(t, err)
		assert.Equal(t, RelaxedTime(time.Date(1981, 02, 03, 14, 15, 16, 172000000, time.UTC)), rt)
	}
	{
		var rt RelaxedTime
		err := rt.UnmarshalText([]byte("1981-02-03T14:15:16Z04:00"))
		assert.EqualError(t, err,
			"parsing time \"1981-02-03T14:15:16Z04:00\": extra text: \"04:00\"")
	}
}
