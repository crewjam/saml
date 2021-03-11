package saml

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

func TestRelaxedTimeFormat(t *testing.T) {
	rt := time.Date(1981, 02, 03, 14, 15, 16, 17, time.UTC)
	assert.Check(t, is.Equal("1981-02-03T14:15:16Z", RelaxedTime(rt).String()))

	buf, err := RelaxedTime(rt).MarshalText()
	assert.Check(t, err)
	assert.Check(t, is.Equal("1981-02-03T14:15:16Z", string(buf)))

	loc, err := time.LoadLocation("America/New_York")
	assert.Check(t, err)
	rt = time.Date(1981, 02, 03, 9, 15, 16, 17, loc)

	assert.Check(t, is.Equal("1981-02-03T14:15:16Z", RelaxedTime(rt).String()))
	buf, err = RelaxedTime(rt).MarshalText()
	assert.Check(t, err)
	assert.Check(t, is.Equal("1981-02-03T14:15:16Z", string(buf)))
}

func TestRelaxedTimeParse(t *testing.T) {
	{
		var rt RelaxedTime
		err := rt.UnmarshalText([]byte("1981-02-03T14:15:16Z"))
		assert.Check(t, err)
		assert.Check(t, is.DeepEqual(
			RelaxedTime(time.Date(1981, 02, 03, 14, 15, 16, 0, time.UTC)),
			rt, cmp.AllowUnexported(RelaxedTime{})))
	}

	{
		var rt RelaxedTime
		err := rt.UnmarshalText([]byte("1981-02-03T14:15:16.178901234Z"))
		assert.Check(t, err)
		assert.Check(t, is.DeepEqual(RelaxedTime(time.Date(1981, 02, 03, 14, 15, 16, 179000000, time.UTC)),
			rt, cmp.AllowUnexported(RelaxedTime{})))
	}
	{
		var rt RelaxedTime
		err := rt.UnmarshalText([]byte("1981-02-03T14:15:16.1717Z"))
		assert.Check(t, err)
		assert.Check(t, is.DeepEqual(RelaxedTime(time.Date(1981, 02, 03, 14, 15, 16, 172000000, time.UTC)),
			rt, cmp.AllowUnexported(RelaxedTime{})))
	}
	{
		var rt RelaxedTime
		err := rt.UnmarshalText([]byte("1981-02-03T14:15:16Z04:00"))
		assert.Check(t, is.Error(err,
			"parsing time \"1981-02-03T14:15:16Z04:00\": extra text: \"04:00\""))
	}
}
