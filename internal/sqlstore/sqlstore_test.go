package sqlstore

import (
	"testing"
	"time"
)

func TestRebind(t *testing.T) {
	q := "DELETE FROM t WHERE a = ? AND b < ?"
	if got, want := PostgreSQL.Rebind(q), "DELETE FROM t WHERE a = $1 AND b < $2"; got != want {
		t.Errorf("PostgreSQL: %q, want %q", got, want)
	}
	for _, d := range []Dialect{MySQL, SQLite} {
		if got := d.Rebind(q); got != q {
			t.Errorf("%s: %q", d, got)
		}
	}
}

func TestCheckTable(t *testing.T) {
	for name, ok := range map[string]bool{
		"saml_replay": true, "app.saml_replay": true, "_x1": true, "A": true,
		"": false, "1x": false, "a.b.c": false, "a.": false, ".a": false, "a-b": false,
		"a b": false, "a;b": false, `a"b`: false, "é": false,
	} {
		if err := CheckTable(name); (err == nil) != ok {
			t.Errorf("CheckTable(%q) = %v", name, err)
		}
	}
}

func TestPurger(t *testing.T) {
	var p Purger
	if !p.Due(time.Hour) {
		t.Error("a new Purger is not due")
	}
	if p.Due(time.Hour) {
		t.Error("due again within the interval")
	}
	if p.Due(0) || p.Due(-1) {
		t.Error("due with no interval")
	}
}
