// Package sqlfake is a database/sql driver for tests that keeps its tables
// in memory. It understands only the few statements the SQL stores of
// x/samlsp/replay and x/samlsp/artifact run, and refuses anything else:
//
//	CREATE TABLE [IF NOT EXISTS] t (col type ..., ...) ...
//	CREATE [UNIQUE] INDEX ...                    (ignored)
//	INSERT INTO t (col, ...) VALUES (p, ...)
//	SELECT col, ... FROM t [WHERE cond AND ...]
//	DELETE FROM t [WHERE cond AND ...]
//
// where each cond is "col op p", op is one of = < <= > >=, and p is a
// placeholder. A column declared PRIMARY KEY is unique: an INSERT of a
// value it already holds fails. Each statement runs atomically, as a
// single-statement transaction does in a real database, but statements
// interleave freely, so that tests can race them.
//
// A DB takes the placeholders of its dialect, $1, $2, ... for PostgreSQL
// and ? for the others, and refuses the other kind, so that a test also
// checks the store's placeholders.
package sqlfake

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/crewjam/saml/internal/sqlstore"
)

// DB is an in-memory database.
type DB struct {
	dialect sqlstore.Dialect
	hook    atomic.Pointer[func(query string)]

	mu     sync.Mutex
	tables map[string]*table
}

type table struct {
	cols []string
	pk   int // index of the PRIMARY KEY column, or -1
	rows [][]driver.Value
}

// New returns an empty DB that takes the placeholders of dialect.
func New(dialect sqlstore.Dialect) *DB {
	return &DB{dialect: dialect, tables: map[string]*table{}}
}

// SQL returns a *sql.DB that runs its statements in db.
func (db *DB) SQL() *sql.DB { return sql.OpenDB(connector{db}) }

// SetHook sets a function called with each statement before it runs, or
// removes it if f is nil. It may be called while db is in use.
func (db *DB) SetHook(f func(query string)) {
	if f == nil {
		db.hook.Store(nil)
		return
	}
	db.hook.Store(&f)
}

// Rows returns the number of rows in the table name, or -1 if there is no
// such table.
func (db *DB) Rows(name string) int {
	db.mu.Lock()
	defer db.mu.Unlock()
	t, ok := db.tables[strings.ToLower(name)]
	if !ok {
		return -1
	}
	return len(t.rows)
}

// Set sets the column col of every row of the table name to v, which lets
// a test change rows behind a store's back.
func (db *DB) Set(name, col string, v driver.Value) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	t, ok := db.tables[strings.ToLower(name)]
	if !ok {
		return fmt.Errorf("no such table: %s", name)
	}
	i := t.col(col)
	if i < 0 {
		return fmt.Errorf("no such column: %s", col)
	}
	for _, r := range t.rows {
		r[i] = v
	}
	return nil
}

func (t *table) col(name string) int {
	for i, c := range t.cols {
		if strings.EqualFold(c, name) {
			return i
		}
	}
	return -1
}

type connector struct{ db *DB }

func (c connector) Connect(context.Context) (driver.Conn, error) { return &conn{c.db}, nil }
func (connector) Driver() driver.Driver                          { return fakeDriver{} }

type fakeDriver struct{}

func (fakeDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("sqlfake: open a DB with sqlfake.New")
}

type conn struct{ db *DB }

func (c *conn) Prepare(query string) (driver.Stmt, error) { return &stmt{c, query}, nil }
func (c *conn) Close() error                              { return nil }
func (c *conn) Begin() (driver.Tx, error) {
	return nil, errors.New("sqlfake: transactions are not supported")
}

func (c *conn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	res, err := c.db.run(query, args)
	if err != nil {
		return nil, err
	}
	return driver.RowsAffected(res.affected), nil
}

func (c *conn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	res, err := c.db.run(query, args)
	if err != nil {
		return nil, err
	}
	if res.cols == nil {
		return nil, errors.New("sqlfake: the statement returns no rows")
	}
	return &rows{cols: res.cols, data: res.rows}, nil
}

type stmt struct {
	c     *conn
	query string
}

func (s *stmt) Close() error  { return nil }
func (s *stmt) NumInput() int { return -1 }

func (s *stmt) Exec(args []driver.Value) (driver.Result, error) {
	return s.c.ExecContext(context.Background(), s.query, named(args))
}

func (s *stmt) Query(args []driver.Value) (driver.Rows, error) {
	return s.c.QueryContext(context.Background(), s.query, named(args))
}

func named(args []driver.Value) []driver.NamedValue {
	nv := make([]driver.NamedValue, len(args))
	for i, a := range args {
		nv[i] = driver.NamedValue{Ordinal: i + 1, Value: a}
	}
	return nv
}

type rows struct {
	cols []string
	data [][]driver.Value
	i    int
}

func (r *rows) Columns() []string { return r.cols }
func (r *rows) Close() error      { return nil }
func (r *rows) Next(dest []driver.Value) error {
	if r.i >= len(r.data) {
		return io.EOF
	}
	copy(dest, r.data[r.i])
	r.i++
	return nil
}

type result struct {
	affected int64
	cols     []string
	rows     [][]driver.Value
}

// run parses query and runs it, atomically.
func (db *DB) run(query string, args []driver.NamedValue) (result, error) {
	if h := db.hook.Load(); h != nil {
		(*h)(query)
	}
	toks, err := tokenize(query)
	if err != nil {
		return result{}, err
	}
	p := &parser{toks: toks, dialect: db.dialect}
	for _, a := range args {
		p.args = append(p.args, a.Value)
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	var res result
	switch {
	case p.accept("CREATE"):
		err = db.create(p)
	case p.accept("INSERT"):
		res, err = db.insert(p)
	case p.accept("SELECT"):
		res, err = db.selectRows(p)
	case p.accept("DELETE"):
		res, err = db.deleteRows(p)
	default:
		err = fmt.Errorf("sqlfake: unsupported statement: %s", query)
	}
	if err != nil {
		return result{}, err
	}
	if p.used != len(p.args) {
		return result{}, fmt.Errorf("sqlfake: %d arguments for %d placeholders", len(p.args), p.used)
	}
	return res, nil
}

func (db *DB) create(p *parser) error {
	if p.accept("UNIQUE") || p.peekIs("INDEX") {
		return nil
	}
	if err := p.expect("TABLE"); err != nil {
		return err
	}
	ifNotExists := false
	if p.accept("IF") {
		if err := p.expect("NOT", "EXISTS"); err != nil {
			return err
		}
		ifNotExists = true
	}
	name := strings.ToLower(p.next())
	if err := p.expect("("); err != nil {
		return err
	}
	t := &table{pk: -1}
	depth := 0
	var item []string
	finish := func() {
		if len(item) == 0 {
			return
		}
		switch strings.ToUpper(item[0]) {
		case "PRIMARY", "INDEX", "KEY", "UNIQUE", "CONSTRAINT":
		default:
			t.cols = append(t.cols, item[0])
			for i := 1; i+1 < len(item); i++ {
				if strings.EqualFold(item[i], "PRIMARY") && strings.EqualFold(item[i+1], "KEY") {
					t.pk = len(t.cols) - 1
				}
			}
		}
		item = nil
	}
	for {
		tok := p.next()
		switch {
		case tok == "":
			return errors.New("sqlfake: unterminated CREATE TABLE")
		case tok == "(":
			depth++
		case tok == ")" && depth == 0:
			finish()
			if _, exists := db.tables[name]; exists {
				if ifNotExists {
					return nil
				}
				return fmt.Errorf("sqlfake: table %s already exists", name)
			}
			p.i = len(p.toks) // ignore table options
			db.tables[name] = t
			return nil
		case tok == ")":
			depth--
		case tok == "," && depth == 0:
			finish()
			continue
		}
		item = append(item, tok)
	}
}

func (db *DB) table(name string) (*table, error) {
	t, ok := db.tables[strings.ToLower(name)]
	if !ok {
		return nil, fmt.Errorf("sqlfake: no such table: %s", name)
	}
	return t, nil
}

func (db *DB) insert(p *parser) (result, error) {
	if err := p.expect("INTO"); err != nil {
		return result{}, err
	}
	t, err := db.table(p.next())
	if err != nil {
		return result{}, err
	}
	cols, err := p.columns(t)
	if err != nil {
		return result{}, err
	}
	if err := p.expect("VALUES", "("); err != nil {
		return result{}, err
	}
	row := make([]driver.Value, len(t.cols))
	for i, c := range cols {
		if i > 0 {
			if err := p.expect(","); err != nil {
				return result{}, err
			}
		}
		v, err := p.value()
		if err != nil {
			return result{}, err
		}
		if b, ok := v.([]byte); ok {
			v = append([]byte(nil), b...)
		}
		row[c] = v
	}
	if err := p.expect(")"); err != nil {
		return result{}, err
	}
	if err := p.end(); err != nil {
		return result{}, err
	}
	if t.pk >= 0 {
		for _, r := range t.rows {
			if eq, _ := compare(r[t.pk], row[t.pk]); eq == 0 {
				return result{}, fmt.Errorf("sqlfake: UNIQUE constraint failed: %s", t.cols[t.pk])
			}
		}
	}
	t.rows = append(t.rows, row)
	return result{affected: 1}, nil
}

func (db *DB) selectRows(p *parser) (result, error) {
	var names []string
	for {
		names = append(names, p.next())
		if !p.accept(",") {
			break
		}
	}
	if err := p.expect("FROM"); err != nil {
		return result{}, err
	}
	t, err := db.table(p.next())
	if err != nil {
		return result{}, err
	}
	idx := make([]int, len(names))
	for i, n := range names {
		if idx[i] = t.col(n); idx[i] < 0 {
			return result{}, fmt.Errorf("sqlfake: no such column: %s", n)
		}
	}
	match, err := p.where(t)
	if err != nil {
		return result{}, err
	}
	res := result{cols: names, rows: [][]driver.Value{}}
	for _, r := range t.rows {
		ok, err := match(r)
		if err != nil {
			return result{}, err
		}
		if !ok {
			continue
		}
		out := make([]driver.Value, len(idx))
		for i, c := range idx {
			out[i] = r[c]
			if b, isBytes := out[i].([]byte); isBytes {
				out[i] = append([]byte(nil), b...)
			}
		}
		res.rows = append(res.rows, out)
	}
	return res, nil
}

func (db *DB) deleteRows(p *parser) (result, error) {
	if err := p.expect("FROM"); err != nil {
		return result{}, err
	}
	t, err := db.table(p.next())
	if err != nil {
		return result{}, err
	}
	match, err := p.where(t)
	if err != nil {
		return result{}, err
	}
	kept := t.rows[:0:0]
	var n int64
	for _, r := range t.rows {
		ok, err := match(r)
		if err != nil {
			return result{}, err
		}
		if ok {
			n++
		} else {
			kept = append(kept, r)
		}
	}
	t.rows = kept
	return result{affected: n}, nil
}

type parser struct {
	toks    []string
	i       int
	dialect sqlstore.Dialect
	args    []driver.Value
	used    int
}

func (p *parser) next() string {
	if p.i >= len(p.toks) {
		return ""
	}
	p.i++
	return p.toks[p.i-1]
}

func (p *parser) peekIs(kw string) bool {
	return p.i < len(p.toks) && strings.EqualFold(p.toks[p.i], kw)
}

func (p *parser) accept(kw string) bool {
	if p.peekIs(kw) {
		p.i++
		return true
	}
	return false
}

func (p *parser) expect(kws ...string) error {
	for _, kw := range kws {
		if !p.accept(kw) {
			got := "the end"
			if p.i < len(p.toks) {
				got = strconv.Quote(p.toks[p.i])
			}
			return fmt.Errorf("sqlfake: expected %s, got %s", kw, got)
		}
	}
	return nil
}

func (p *parser) end() error {
	p.accept(";")
	if p.i != len(p.toks) {
		return fmt.Errorf("sqlfake: unexpected %q", p.toks[p.i])
	}
	return nil
}

// columns reads a parenthesized list of column names of t.
func (p *parser) columns(t *table) ([]int, error) {
	if err := p.expect("("); err != nil {
		return nil, err
	}
	var cols []int
	for {
		name := p.next()
		c := t.col(name)
		if c < 0 {
			return nil, fmt.Errorf("sqlfake: no such column: %s", name)
		}
		cols = append(cols, c)
		if !p.accept(",") {
			break
		}
	}
	if err := p.expect(")"); err != nil {
		return nil, err
	}
	return cols, nil
}

// value reads a placeholder and returns its argument.
func (p *parser) value() (driver.Value, error) {
	tok := p.next()
	var n int
	switch {
	case tok == "?" && p.dialect != sqlstore.PostgreSQL:
		n = p.used
	case strings.HasPrefix(tok, "$") && p.dialect == sqlstore.PostgreSQL:
		i, err := strconv.Atoi(tok[1:])
		if err != nil || i < 1 {
			return nil, fmt.Errorf("sqlfake: bad placeholder %s", tok)
		}
		if i != p.used+1 {
			return nil, fmt.Errorf("sqlfake: placeholder %s out of order", tok)
		}
		n = i - 1
	default:
		return nil, fmt.Errorf("sqlfake: %q is not a placeholder of %s", tok, p.dialect)
	}
	if n >= len(p.args) {
		return nil, fmt.Errorf("sqlfake: no argument for placeholder %s", tok)
	}
	p.used++
	return p.args[n], nil
}

// where reads an optional WHERE clause to the end of the statement and
// returns its test of a row of t.
func (p *parser) where(t *table) (func([]driver.Value) (bool, error), error) {
	type cond struct {
		col int
		op  string
		v   driver.Value
	}
	var conds []cond
	if p.accept("WHERE") {
		for {
			name := p.next()
			c := t.col(name)
			if c < 0 {
				return nil, fmt.Errorf("sqlfake: no such column: %s", name)
			}
			op := p.next()
			switch op {
			case "=", "<", "<=", ">", ">=":
			default:
				return nil, fmt.Errorf("sqlfake: unsupported operator %q", op)
			}
			v, err := p.value()
			if err != nil {
				return nil, err
			}
			conds = append(conds, cond{c, op, v})
			if !p.accept("AND") {
				break
			}
		}
	}
	if err := p.end(); err != nil {
		return nil, err
	}
	return func(r []driver.Value) (bool, error) {
		for _, c := range conds {
			cmp, err := compare(r[c.col], c.v)
			if err != nil {
				return false, err
			}
			var ok bool
			switch c.op {
			case "=":
				ok = cmp == 0
			case "<":
				ok = cmp < 0
			case "<=":
				ok = cmp <= 0
			case ">":
				ok = cmp > 0
			case ">=":
				ok = cmp >= 0
			}
			if !ok {
				return false, nil
			}
		}
		return true, nil
	}, nil
}

// compare compares two values of the same kind: integers, or strings and
// byte slices.
func compare(a, b driver.Value) (int, error) {
	switch a := a.(type) {
	case int64:
		if b, ok := b.(int64); ok {
			switch {
			case a < b:
				return -1, nil
			case a > b:
				return 1, nil
			}
			return 0, nil
		}
	case string, []byte:
		if s, ok := text(b); ok {
			t, _ := text(a)
			return strings.Compare(t, s), nil
		}
	}
	return 0, fmt.Errorf("sqlfake: cannot compare %T with %T", a, b)
}

func text(v driver.Value) (string, bool) {
	switch v := v.(type) {
	case string:
		return v, true
	case []byte:
		return string(v), true
	}
	return "", false
}

// isWordByte reports whether c may be part of an identifier, keyword or
// number.
func isWordByte(c byte) bool {
	return c == '_' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9'
}

func tokenize(q string) ([]string, error) {
	var toks []string
	for i := 0; i < len(q); {
		c := q[i]
		switch {
		case strings.IndexByte(" \t\n\r", c) >= 0:
			i++
		case isWordByte(c):
			j := i
			for j < len(q) && (isWordByte(q[j]) || q[j] == '.') {
				j++
			}
			toks = append(toks, q[i:j])
			i = j
		case c == '$':
			j := i + 1
			for j < len(q) && '0' <= q[j] && q[j] <= '9' {
				j++
			}
			toks = append(toks, q[i:j])
			i = j
		case (c == '<' || c == '>') && i+1 < len(q) && q[i+1] == '=':
			toks = append(toks, q[i:i+2])
			i += 2
		case strings.IndexByte("(),=<>?*;", c) >= 0:
			toks = append(toks, q[i:i+1])
			i++
		default:
			return nil, fmt.Errorf("sqlfake: unexpected %q in %q", c, q)
		}
	}
	return toks, nil
}
