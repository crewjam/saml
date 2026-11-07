package saml

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Duration is a time.Duration that uses the xsd:duration format for text
// marshalling and unmarshalling.
type Duration time.Duration

// MarshalText implements the encoding.TextMarshaler interface.
//
// The duration is written with hours, minutes and seconds only (never
// years, months or days, whose length is not fixed), so that it reads back
// as exactly the same value.
func (d Duration) MarshalText() ([]byte, error) {
	if d == 0 {
		return nil, nil
	}

	out := "PT"
	// The magnitude is computed in uint64 so that the most negative
	// Duration, whose magnitude does not fit in an int64, is written
	// correctly.
	magnitude := uint64(d) //nolint:gosec // G115: two's-complement wrap is intended; negated below
	if d < 0 {
		magnitude = -magnitude
		out = "-" + out
	}

	h := magnitude / uint64(time.Hour)
	m := magnitude % uint64(time.Hour) / uint64(time.Minute)
	s := magnitude % uint64(time.Minute) / uint64(time.Second)
	ns := magnitude % uint64(time.Second)
	if h > 0 {
		out += fmt.Sprintf("%dH", h)
	}
	if m > 0 {
		out += fmt.Sprintf("%dM", m)
	}
	if s > 0 || ns > 0 {
		out += fmt.Sprintf("%d", s)
		if ns > 0 {
			out += strings.TrimRight(fmt.Sprintf(".%09d", ns), "0")
		}
		out += "S"
	}

	return []byte(out), nil
}

const (
	day   = 24 * time.Hour
	month = 30 * day  // Assumed to be 30 days.
	year  = 365 * day // Assumed to be non-leap year.
)

var (
	durationRegexp     = regexp.MustCompile(`^(-?)P(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)D)?(?:T(.+))?$`)
	durationTimeRegexp = regexp.MustCompile(`^(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?$`)
)

// UnmarshalText implements the encoding.TextUnmarshaler interface.
//
// Leading and trailing XML whitespace is ignored, as the xsd:duration type's
// whiteSpace facet ("collapse") requires. A year is taken to be 365 days and
// a month 30 days. Fractions of a second smaller than a nanosecond are
// dropped. A duration that does not fit in a time.Duration is an error,
// rather than a value that silently wraps around.
func (d *Duration) UnmarshalText(text []byte) error {
	if text == nil {
		*d = 0
		return nil
	}

	trimmed := strings.Trim(string(text), " \t\r\n")
	match := durationRegexp.FindStringSubmatch(trimmed)
	if match == nil || strings.Join(match[2:6], "") == "" {
		return fmt.Errorf("invalid duration (%s)", text)
	}

	// The magnitude is accumulated in uint64, so that the most negative
	// Duration (whose magnitude is one more than the largest positive one)
	// can be read back.
	limit := uint64(math.MaxInt64)
	negative := match[1] == "-"
	if negative {
		limit++
	}
	var out uint64
	add := func(what, digits string, unit time.Duration) error {
		if digits == "" {
			return nil
		}
		n, err := strconv.ParseUint(digits, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid duration %s (%s): %w", what, text, err)
		}
		if n > (limit-out)/uint64(unit) { //nolint:gosec // G115: unit is a positive time constant
			return fmt.Errorf("invalid duration (%s): out of range", text)
		}
		out += n * uint64(unit) //nolint:gosec // G115: unit is a positive time constant; overflow is checked above
		return nil
	}

	if err := add("years", match[2], year); err != nil {
		return err
	}
	if err := add("months", match[3], month); err != nil {
		return err
	}
	if err := add("days", match[4], day); err != nil {
		return err
	}
	if match[5] != "" {
		match := durationTimeRegexp.FindStringSubmatch(match[5])
		if match == nil {
			return fmt.Errorf("invalid duration (%s)", text)
		}
		if err := add("hours", match[1], time.Hour); err != nil {
			return err
		}
		if err := add("minutes", match[2], time.Minute); err != nil {
			return err
		}
		if match[3] != "" {
			// The seconds are read as an integer and a fraction rather than
			// as a float, which would round (1.005s is not exactly
			// representable) and has no defined conversion when out of range.
			whole, fraction, _ := strings.Cut(match[3], ".")
			if err := add("seconds", whole, time.Second); err != nil {
				return err
			}
			if fraction != "" {
				if len(fraction) > 9 {
					fraction = fraction[:9]
				}
				fraction += strings.Repeat("0", 9-len(fraction))
				if err := add("seconds", fraction, time.Nanosecond); err != nil {
					return err
				}
			}
		}
	}

	if negative {
		*d = Duration(-out) //nolint:gosec // G115: out <= 1<<63, so -out wraps to the intended negative value
	} else {
		*d = Duration(out) //nolint:gosec // G115: out <= math.MaxInt64 when not negative (checked above)
	}
	return nil
}
