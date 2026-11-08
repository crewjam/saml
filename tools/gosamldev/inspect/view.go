package inspect

import (
	"fmt"
	"regexp"
	"strings"
)

// View is a message as the pages show it: a title, short checks, field
// groups, explanations of what looks wrong, and the XML as highlighting
// tokens. The in-browser inspector and the server's log entry page both
// render it, so they show a message the same way.
type View struct {
	Title  string      `json:"title"`
	Sub    string      `json:"sub"`
	Checks []ViewCheck `json:"checks,omitempty"`
	Groups []ViewGroup `json:"groups,omitempty"`
	// Notes explain the warnings, one sentence each.
	Notes []string   `json:"notes,omitempty"`
	XML   []XMLToken `json:"xml,omitempty"`
}

// ViewCheck is a short verdict: Level is "ok", "warn" or "bad".
type ViewCheck struct {
	Level string `json:"level"`
	Text  string `json:"text"`
}

// ViewGroup is a titled group of fields.
type ViewGroup struct {
	Title string    `json:"title"`
	Rows  []ViewRow `json:"rows"`
}

// ViewRow is one field. Mono says whether its value is a technical value
// (a URL, ID, URN, algorithm) set in monospace; Time whether it is a time,
// which never is.
type ViewRow struct {
	K    string `json:"k"`
	V    string `json:"v"`
	Mono bool   `json:"mono,omitempty"`
	Time bool   `json:"time,omitempty"`
}

// XMLToken is a piece of XML for highlighting: Kind is "tag", "attr",
// "val", "com" or "text".
type XMLToken struct {
	Kind string `json:"k"`
	Text string `json:"t"`
}

// addViews sets the View of each message of res.
func addViews(res *Result) {
	for _, m := range res.Messages {
		m.View = viewOf(res, m)
	}
}

func viewOf(res *Result, m *Message) *View {
	v := &View{Title: m.Type}
	var sub []string
	if res.Binding != "" && m.Parameter != "" {
		sub = append(sub, strings.TrimSuffix(res.Binding, " (signed in the query string)"))
	}
	if m.Encoding != "" {
		sub = append(sub, m.Encoding)
	}
	if n := len(m.raw); n > 0 {
		sub = append(sub, byteSize(n))
	}
	v.Sub = strings.Join(sub, " · ")

	if m.Error != "" {
		v.Checks = append(v.Checks, ViewCheck{"bad", m.Error})
	}
	for _, s := range m.Sections {
		if !strings.HasSuffix(s.Title, "Status") {
			continue
		}
		for _, r := range s.Rows {
			if r.K == "StatusCode" {
				if strings.HasSuffix(r.V, ":Success") {
					v.Checks = append(v.Checks, ViewCheck{"ok", "Status Success"})
				} else {
					v.Checks = append(v.Checks, ViewCheck{"bad", "Status " + shortURN(r.V)})
				}
			}
		}
	}
	for _, sig := range m.Signatures {
		element, _, _ := strings.Cut(sig.Signs, " ")
		switch {
		case sig.Trust != nil && sig.Trust.OK:
			v.Checks = append(v.Checks, ViewCheck{"ok", element + " signature valid"})
		case sig.Trust != nil:
			v.Checks = append(v.Checks, ViewCheck{"bad", element + " signature not trusted"})
		case sig.Integrity != nil && !sig.Integrity.OK:
			v.Checks = append(v.Checks, ViewCheck{"bad", element + " signature broken"})
		default:
			v.Checks = append(v.Checks, ViewCheck{"ok", element + " signed"})
		}
	}
	if m.Type == "Response" {
		responseSigned, assertionSigned := false, false
		for _, sig := range m.Signatures {
			responseSigned = responseSigned || strings.HasPrefix(sig.Signs, "Response")
			assertionSigned = assertionSigned || strings.HasPrefix(sig.Signs, "Assertion")
		}
		if !responseSigned && (assertionSigned || hasSection(m, "EncryptedAssertion")) {
			v.Checks = append(v.Checks, ViewCheck{"warn", "Response not signed"})
		}
	}
	if hasSection(m, "Decrypted") {
		v.Checks = append(v.Checks, ViewCheck{"ok", "Decrypted"})
	} else if hasSection(m, "EncryptedAssertion") {
		v.Checks = append(v.Checks, ViewCheck{"warn", "Assertion encrypted"})
	}

	for _, s := range m.Sections {
		g := ViewGroup{Title: s.Title}
		for _, r := range s.Rows {
			row := ViewRow{K: strings.TrimSpace(r.K), V: r.V}
			row.Time = isTime(r.V)
			row.Mono = !row.Time && isTechnical(r.V)
			g.Rows = append(g.Rows, row)
		}
		v.Groups = append(v.Groups, g)
	}
	v.Notes = append(v.Notes, m.Warnings...)
	v.XML = HighlightXML(m.XML)
	return v
}

func hasSection(m *Message, suffix string) bool {
	for _, s := range m.Sections {
		if strings.HasSuffix(s.Title, suffix) {
			return true
		}
	}
	return false
}

var timeValue = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}`)

func isTime(v string) bool { return timeValue.MatchString(v) }

// isTechnical reports whether a value is a technical one, to be set in
// monospace: anything but words and short phrases.
func isTechnical(v string) bool {
	switch strings.ToLower(v) {
	case "yes", "no", "true", "false", "(present)", "(no values)", "(nil)":
		return false
	}
	if strings.Contains(v, "://") || strings.Contains(v, "urn:") || strings.Contains(v, "@") {
		return true
	}
	// A sentence or phrase is not technical.
	return strings.Count(v, " ") < 2
}

func byteSize(n int) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	return fmt.Sprintf("%.1f KB", float64(n)/1024)
}

var attrPattern = regexp.MustCompile(`(\s+)([^\s=/>]+)(\s*=\s*)("[^"]*"|'[^']*')?`)

// HighlightXML splits XML into tokens for highlighting. It does not parse
// it: malformed XML is tokenized as best it can be, and the text of the
// tokens always adds up to xml.
func HighlightXML(xml string) []XMLToken {
	var out []XMLToken
	add := func(kind, text string) {
		if text == "" {
			return
		}
		if n := len(out); n > 0 && out[n-1].Kind == kind {
			out[n-1].Text += text
			return
		}
		out = append(out, XMLToken{kind, text})
	}
	for i := 0; i < len(xml); {
		if xml[i] != '<' {
			j := strings.IndexByte(xml[i:], '<')
			if j < 0 {
				j = len(xml) - i
			}
			add("text", xml[i:i+j])
			i += j
			continue
		}
		if strings.HasPrefix(xml[i:], "<!--") {
			end := strings.Index(xml[i:], "-->")
			if end < 0 {
				add("com", xml[i:])
				break
			}
			add("com", xml[i:i+end+3])
			i += end + 3
			continue
		}
		// A tag: find its end, outside quotes.
		end, quote := -1, byte(0)
		for j := i + 1; j < len(xml); j++ {
			c := xml[j]
			switch {
			case quote != 0:
				if c == quote {
					quote = 0
				}
			case c == '"' || c == '\'':
				quote = c
			case c == '>':
				end = j
			}
			if end >= 0 {
				break
			}
		}
		if end < 0 {
			add("text", xml[i:])
			break
		}
		tag := xml[i : end+1]
		i = end + 1
		nameEnd := strings.IndexAny(tag, " \t\r\n/>")
		if nameEnd <= 1 && strings.HasPrefix(tag, "</") {
			nameEnd = strings.IndexAny(tag[2:], " \t\r\n>") + 2
		}
		if nameEnd < 1 {
			add("tag", tag)
			continue
		}
		add("tag", tag[:nameEnd])
		rest := tag[nameEnd:]
		for {
			loc := attrPattern.FindStringSubmatchIndex(rest)
			if loc == nil || loc[0] != 0 {
				break
			}
			add("text", rest[loc[2]:loc[3]])
			add("attr", rest[loc[4]:loc[5]])
			add("text", rest[loc[6]:loc[7]])
			if loc[8] >= 0 {
				add("val", rest[loc[8]:loc[9]])
			}
			rest = rest[loc[1]:]
		}
		add("tag", rest)
	}
	return out
}
