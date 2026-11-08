// Command gendoc writes the package documentation of package saml, saml.go,
// from README.md, converting its Markdown to Go doc comment syntax
// (https://go.dev/doc/comment): headings, code blocks, links and lists. It
// is run by go generate in the module root.
package main

import (
	"bytes"
	"fmt"
	"go/format"
	"log"
	"os"
	"regexp"
	"strings"
)

func main() {
	if len(os.Args) != 3 {
		log.Fatal("usage: gendoc README.md saml.go")
	}
	readme, err := os.ReadFile(os.Args[1]) //nolint:gosec // the path is given by go:generate
	if err != nil {
		log.Fatal(err)
	}
	doc, err := convert(string(readme))
	if err != nil {
		log.Fatal(err)
	}
	var src bytes.Buffer
	for _, line := range strings.Split(strings.TrimRight(doc, "\n"), "\n") {
		if line == "" {
			src.WriteString("//\n")
		} else {
			src.WriteString("// " + line + "\n")
		}
	}
	src.WriteString("package saml\n")
	out, err := format.Source(src.Bytes())
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(os.Args[2], out, 0o600); err != nil { //nolint:gosec // the path is given by go:generate
		log.Fatal(err)
	}
}

var (
	heading    = regexp.MustCompile(`^#{2,6} (.*)$`)
	fence      = regexp.MustCompile("^( *)```")
	link       = regexp.MustCompile(`\[([^\]]+)\]\(([^)\s]+)\)`)
	bold       = regexp.MustCompile(`\*\*([^*]+)\*\*`)
	italic     = regexp.MustCompile(`(^|[\s(])_([^_]+)_([\s).,:;]|$)`)
	code       = regexp.MustCompile("`([^`]*)`")
	tableSep   = regexp.MustCompile(`^\|[-| :]+\|$`)
	listMarker = regexp.MustCompile(`^( *)([-*]|\d+\.) `)
)

// convert returns the text of README, from the line that starts with
// "Package saml", in Go doc comment syntax.
func convert(readme string) (string, error) {
	i := strings.Index(readme, "\nPackage saml")
	if i < 0 {
		return "", fmt.Errorf("README.md has no line starting with %q", "Package saml")
	}
	c := &converter{links: map[string]string{}, listStart: -1}
	for _, line := range strings.Split(readme[i+1:], "\n") {
		c.line(line)
	}
	if c.inFence {
		return "", fmt.Errorf("README.md has an unclosed code block")
	}
	c.flushTable()
	c.endList()

	text := strings.TrimRight(strings.Join(c.out, "\n"), "\n") + "\n"
	if len(c.order) > 0 {
		text += "\n"
		for _, name := range c.order {
			text += "[" + name + "]: " + c.links[name] + "\n"
		}
	}
	return text, nil
}

type converter struct {
	out []string

	inFence     bool
	fenceIndent int
	table       []string

	// The list being written: where it starts in out, whether it is
	// numbered, its last number, and whether an item holds code.
	listStart  int
	ordered    bool
	number     int
	codeInList bool

	links map[string]string // link text to URL
	order []string
}

// line converts one line of Markdown.
func (c *converter) line(line string) {
	if m := fence.FindStringSubmatch(line); m != nil {
		c.inFence = !c.inFence
		c.fenceIndent = len(m[1])
		if c.inFence && c.fenceIndent > 0 && c.listStart >= 0 {
			c.codeInList = true
		}
		return
	}
	if c.inFence {
		line = strings.TrimPrefix(line, strings.Repeat(" ", c.fenceIndent))
		if strings.TrimSpace(line) == "" {
			c.out = append(c.out, "")
		} else {
			c.out = append(c.out, "\t"+line)
		}
		return
	}
	if strings.HasPrefix(line, "|") {
		c.table = append(c.table, line)
		return
	}
	c.flushTable()
	if c.listStart >= 0 && line != "" && !strings.HasPrefix(line, " ") && !listMarker.MatchString(line) {
		c.endList()
	}
	switch {
	case strings.HasPrefix(line, "    "):
		// An indented code block.
		c.out = append(c.out, "\t"+strings.TrimPrefix(line, "    "))
	case heading.MatchString(line):
		c.out = append(c.out, "# "+c.inline(heading.FindStringSubmatch(line)[1]))
	case listMarker.MatchString(line):
		c.listItem(line)
	default:
		c.out = append(c.out, c.inline(line))
	}
}

// listItem converts a line that starts a list item.
func (c *converter) listItem(line string) {
	m := listMarker.FindStringSubmatch(line)
	marker := m[2]
	ordered := marker != "-" && marker != "*"
	if c.listStart >= 0 && m[1] == "" && ordered != c.ordered {
		c.endList() // a list of the other kind starts
	}
	if c.listStart < 0 {
		c.listStart, c.ordered = len(c.out), ordered
	}
	if ordered {
		// Markdown numbers the items itself; Go doc shows the numbers given.
		c.number++
		marker = fmt.Sprintf("%d.", c.number)
	}
	c.out = append(c.out, "  "+m[1]+marker+" "+c.inline(line[len(m[0]):]))
}

// endList ends the list being written. Go doc list items hold only
// paragraphs, so a list with a code block in an item becomes plain
// paragraphs, and the code a code block.
func (c *converter) endList() {
	if c.listStart >= 0 && c.codeInList {
		for i := c.listStart; i < len(c.out); i++ {
			if strings.HasPrefix(c.out[i], "\t") {
				continue
			}
			line := strings.TrimLeft(c.out[i], " ")
			if m := listMarker.FindString(line); m != "" {
				line = line[len(m):]
			}
			c.out[i] = line
		}
	}
	c.listStart, c.codeInList, c.number = -1, false, 0
}

// flushTable converts the Markdown table read so far to a list, one item
// per row: the first cell, then the others labelled with their column
// headings.
func (c *converter) flushTable() {
	if c.table == nil {
		return
	}
	var header []string
	for _, row := range c.table {
		if tableSep.MatchString(row) {
			continue
		}
		cells := strings.Split(strings.Trim(row, "|"), "|")
		for i := range cells {
			cells[i] = c.inline(strings.TrimSpace(cells[i]))
		}
		if header == nil {
			header = cells
			continue
		}
		item := "  - " + cells[0]
		for i := 1; i < len(cells) && i < len(header); i++ {
			item += ". " + header[i] + ": " + cells[i]
		}
		c.out = append(c.out, item, "")
	}
	c.table = nil
}

// inline converts the inline Markdown of a line of prose: links, emphasis
// and code spans.
func (c *converter) inline(s string) string {
	s = link.ReplaceAllStringFunc(s, func(m string) string {
		parts := link.FindStringSubmatch(m)
		text, target := code.ReplaceAllString(parts[1], "$1"), parts[2]
		if strings.HasPrefix(target, "#") {
			return text // a link to a section of the README
		}
		if !strings.Contains(target, "://") {
			// A file of the repository.
			target = "https://github.com/crewjam/saml/blob/main/" + strings.TrimPrefix(target, "./")
		}
		if url, ok := c.links[text]; ok && url != target {
			return text + " (" + target + ")"
		}
		if _, ok := c.links[text]; !ok {
			c.links[text] = target
			c.order = append(c.order, text)
		}
		return "[" + text + "]"
	})
	s = bold.ReplaceAllString(s, "$1")
	s = italic.ReplaceAllString(s, "$1$2$3")
	return code.ReplaceAllString(s, "$1")
}
