package xmlroundtrip

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"gotest.tools/v3/assert"
)

func TestValidateRefusesTooManyNamespacesInScope(t *testing.T) {
	var b strings.Builder
	// Two declarations per element, so the depth stays under MaxDepth.
	for i := 0; i <= MaxNamespacesInScope/2; i++ {
		fmt.Fprintf(&b, `<e%d xmlns:p%d="urn:p" xmlns:q%d="urn:q">`, i, i, i)
	}
	assert.Check(t, errors.Is(Validate([]byte(b.String())), ErrTooManyNamespaces))
}

// Declarations repeated on sibling elements, as some IdPs write xmlns:xs and
// xmlns:xsi on every AttributeValue, are never in scope together.
func TestValidateAcceptsRepeatedSiblingNamespaces(t *testing.T) {
	sibling := `<v xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">x</v>`
	assert.NilError(t, Validate([]byte("<r>"+strings.Repeat(sibling, 10*MaxNamespacesInScope)+"</r>")))
}

func TestValidateDepthLimit(t *testing.T) {
	nest := func(n int) []byte { return []byte(strings.Repeat("<a>", n) + strings.Repeat("</a>", n)) }
	assert.NilError(t, Validate(nest(MaxDepth)))
	assert.Check(t, errors.Is(Validate(nest(MaxDepth+1)), ErrTooDeep))
}
