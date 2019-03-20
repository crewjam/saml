package saml

import (
	"crypto/rand"
	"strconv"
	"strings"
	"time"

	"github.com/russellhaering/goxmldsig"
)

// TimeNow is a function that returns the current time. The default
// value is time.Now, but it can be replaced for testing.
var TimeNow = func() time.Time { return time.Now().UTC() }

// Clock is assigned to dsig validation and signing contexts if it is
// not nil, otherwise the default clock is used.
var Clock *dsig.Clock

// RandReader is the io.Reader that produces cryptographically random
// bytes when they are need by the library. The default value is
// rand.Reader, but it can be replaced for testing.
var RandReader = rand.Reader

func randomBytes(n int) []byte {
	rv := make([]byte, n)
	if _, err := RandReader.Read(rv); err != nil {
		panic(err)
	}
	return rv
}

func GetValidDuration(samlTime string) time.Time {
	// TODO: Add support for negative cache duration

	samlTime = strings.ToLower(samlTime)

	if samlTime[0] != 'p' {
		parsedTime, err := strconv.ParseInt(samlTime, 10, 64)
		if err != nil {
			return TimeNow().Add(time.Duration(time.Hour * 24 * 2))
		}

		return TimeNow().Add(time.Duration(parsedTime))
	}

	//strip P
	samlTime = samlTime[1:]

	samlTime, yearVal := getCacheTimeValue(samlTime, "y")
	samlTime, monthVal := getCacheTimeValue(samlTime, "m")
	samlTime, dayVal := getCacheTimeValue(samlTime, "d")

	currentTime := TimeNow()
	currentTime = currentTime.AddDate(yearVal, monthVal, dayVal)

	if samlTime == "" {
		return currentTime
	}

	//strip T
	samlTime = samlTime[1:]
	samlTime, hourVal := getCacheTimeValue(samlTime, "h")
	samlTime, minuteVal := getCacheTimeValue(samlTime, "m")
	_, secondVal := getCacheTimeValue(samlTime, "s")

	currentTime = currentTime.Add(time.Duration(hourVal) * time.Hour)
	currentTime = currentTime.Add(time.Duration(minuteVal) * time.Minute)
	currentTime = currentTime.Add(time.Duration(secondVal) * time.Second)

	return currentTime
}

func getCacheTimeValue(samlTime string, valType string) (string, int) {
	result := 0
	splitTime := strings.Split(samlTime, valType)
	if len(splitTime) > 0 {
		result, _ = strconv.Atoi(splitTime[0])
		samlTime = strings.Replace(samlTime, splitTime[0]+valType, "", 1)
	}

	return samlTime, result
}
