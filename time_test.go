package saml

import (
	"time"

	. "gopkg.in/check.v1"
)

var _ = Suite(&TimeTest{})

type TimeTest struct {
}

func (test *TimeTest) TestFormat(c *C) {
	t := time.Date(1981, 02, 03, 14, 15, 16, 17, time.UTC)
	c.Assert(RelaxedTime(t).String(), Equals, "1981-02-03T14:15:16Z")

	buf, err := RelaxedTime(t).MarshalText()
	c.Assert(err, IsNil)
	c.Assert(string(buf), Equals, "1981-02-03T14:15:16Z")

	loc, err := time.LoadLocation("America/New_York")
	c.Assert(err, IsNil)
	t = time.Date(1981, 02, 03, 9, 15, 16, 17, loc)

	c.Assert(RelaxedTime(t).String(), Equals, "1981-02-03T14:15:16Z")
	buf, err = RelaxedTime(t).MarshalText()
	c.Assert(err, IsNil)
	c.Assert(string(buf), Equals, "1981-02-03T14:15:16Z")
}

func (test *TimeTest) TestParse(c *C) {
	{
		var t RelaxedTime
		err := t.UnmarshalText([]byte("1981-02-03T14:15:16Z"))
		c.Assert(err, IsNil)
		c.Assert(t, DeepEquals, RelaxedTime(time.Date(1981, 02, 03, 14, 15, 16, 0, time.UTC)))
	}

	{
		var t RelaxedTime
		err := t.UnmarshalText([]byte("1981-02-03T14:15:16.178901234Z"))
		c.Assert(err, IsNil)
		c.Assert(t, DeepEquals, RelaxedTime(time.Date(1981, 02, 03, 14, 15, 16, 179000000, time.UTC)))
	}
	{
		var t RelaxedTime
		err := t.UnmarshalText([]byte("1981-02-03T14:15:16.1717Z"))
		c.Assert(err, IsNil)
		c.Assert(t, DeepEquals, RelaxedTime(time.Date(1981, 02, 03, 14, 15, 16, 172000000, time.UTC)))
	}
	{
		var t RelaxedTime
		err := t.UnmarshalText([]byte("1981-02-03T14:15:16Z04:00"))
		c.Assert(err, ErrorMatches, "parsing time \"1981-02-03T14:15:16Z04:00\": extra text: 04:00")
	}
}
