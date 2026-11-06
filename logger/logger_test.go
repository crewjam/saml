package logger

import (
	"bytes"
	"log"
	"testing"
)

// DefaultLogger satisfies Interface; this fails to compile otherwise.
var _ Interface = DefaultLogger

func TestDefaultLoggerIsSet(t *testing.T) {
	if DefaultLogger == nil {
		t.Fatal("DefaultLogger is nil")
	}
}

// A *log.Logger, which DefaultLogger is, satisfies Interface and its print
// methods write where it is pointed.
func TestStdLoggerSatisfiesInterface(t *testing.T) {
	var buf bytes.Buffer
	var l Interface = log.New(&buf, "", 0)
	l.Printf("a%d", 1)
	l.Print("b")
	l.Println("c")
	if got, want := buf.String(), "a1\nb\nc\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
