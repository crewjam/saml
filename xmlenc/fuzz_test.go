//go:build gofuzz
// +build gofuzz

package xmlenc

import (
	"io/ioutil"
	"testing"

	"strings"
)

func TestPastFuzzingFailures(t *testing.T) {
	entries, err := ioutil.ReadDir("crashers")
	if err != nil {
		t.Errorf("%s", err)
		return
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".output") {
			continue
		}
		if strings.HasSuffix(entry.Name(), ".quoted") {
			continue
		}
		t.Logf("%s", entry.Name())
		data, err := ioutil.ReadFile("crashers/" + entry.Name())
		if err != nil {
			t.Errorf("%s: %s", entry.Name(), err)
			return
		}
		Fuzz(data)
	}
}
