package main

import (
	"strings"
	"testing"
)

func TestConvert(t *testing.T) {
	const readme = "# Title\n\nignored\nPackage saml does things.\n\n" +
		"## Heading\n\n" +
		"Some **bold** and `code`, a [link](https://example.com/) and [a section](#heading).\n\n" +
		"```golang\nfunc main() {\n\tx()\n}\n```\n\n" +
		"    indented code\n\n" +
		"1. first\n\n1. second\n\n" +
		"- **Item.** with code:\n\n  ```golang\n  y()\n  ```\n\n  More.\n\n" +
		"After.\n\n" +
		"| A | B |\n|---|---|\n| x | y |\n\n" +
		"See [SECURITY.md](SECURITY.md).\n"
	got, err := convert(readme)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Package saml does things.\n",
		"# Heading\n",
		"Some bold and code, a [link] and a section.\n",
		"\tfunc main() {\n\t\tx()\n\t}\n",
		"\tindented code\n",
		"  1. first\n\n  2. second\n",
		"Item. with code:\n\n\ty()\n\nMore.\n\nAfter.\n",
		"  - x. B: y\n",
		"[link]: https://example.com/\n",
		"[SECURITY.md]: https://github.com/crewjam/saml/blob/main/SECURITY.md\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	for _, unwanted := range []string{"```", "**", "](", "ignored", "# Title"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("%q left in:\n%s", unwanted, got)
		}
	}
}
