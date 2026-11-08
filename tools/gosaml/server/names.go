package server

import (
	petname "github.com/dustinkirkland/golang-petname"
)

// Instances are named with memorable words rather than random strings,
// since people copy their URLs between systems and read them in logs.
// gosaml.dev is for testing, so neither name is meant to be hard to guess.

// newInstanceID returns a public ID, the name of an instance in its
// protocol URLs, such as "comic-krill". attempt counts earlier names that
// were taken: after a few, a number is added.
func newInstanceID(attempt int) string {
	return withNumber(petname.Generate(2, "-"), attempt)
}

// newInstanceSecret returns the name of an instance's management page,
// such as "wholly-blessed-mammoth": three words, so that two people are
// unlikely to land on each other's instance by accident.
func newInstanceSecret(attempt int) string {
	return withNumber(petname.Generate(3, "-"), attempt)
}

func withNumber(name string, attempt int) string {
	if attempt < 3 {
		return name
	}
	return name + "-" + randomDigits(3)
}
