// A space then `#` starts a YAML comment even mid-value, so an unquoted
// description such as "requires a passkey (`Config.AdminPasskey`, #82)."
// reaches every OpenAPI reader cut short after the comma -- and the file still
// parses, so nothing else notices (#98). v0.3.0 shipped nine of them.
package contracttest

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// yamlKeyLine splits a mapping line into indent, key and value; the
// key may follow a sequence dash and may be quoted.
var yamlKeyLine = regexp.MustCompile(`^(\s*)(?:- )?("[^"]*"|'[^']*'|[^\s"'#][^:]*?):(?:\s+(.*))?$`)

// cutPlainValues returns the 1-based lines on which an unquoted value
// is followed by a comment, which YAML drops. It is a line scanner, not
// a parser: it skips block scalars (`|`, `>`) and quoted values, and
// treats every other value or continuation line as plain.
func cutPlainValues(src string) []int {
	var cut []int
	blockIndent := -1 // indent of the key that opened a block scalar
	quote := byte(0)  // the quote a multi-line quoted value is still inside
	for i, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if blockIndent >= 0 {
			if trimmed == "" || indent > blockIndent {
				continue
			}
			blockIndent = -1
		}
		if quote != 0 {
			if closesQuote(trimmed, quote) {
				quote = 0
			}
			continue
		}
		if trimmed == "" || trimmed[0] == '#' {
			continue
		}
		value := trimmed
		if m := yamlKeyLine.FindStringSubmatch(line); m != nil {
			value = m[3]
			if value == "" {
				continue
			}
			if value[0] == '|' || value[0] == '>' {
				blockIndent = len(m[1])
				continue
			}
		} else if strings.HasPrefix(value, "- ") {
			value = strings.TrimSpace(value[2:])
		}
		if value[0] == '"' || value[0] == '\'' {
			if !closesQuote(value[1:], value[0]) {
				quote = value[0]
			}
			continue
		}
		if strings.Contains(value, " #") {
			cut = append(cut, i+1)
		}
	}
	return cut
}

// closesQuote reports whether s holds the end of a value quoted with q:
// an unescaped `"`, or a `'` not doubled.
func closesQuote(s string, q byte) bool {
	for i := 0; i < len(s); i++ {
		switch {
		case q == '"' && s[i] == '\\':
			i++
		case s[i] == q && q == '\'' && i+1 < len(s) && s[i+1] == '\'':
			i++
		case s[i] == q:
			return true
		}
	}
	return false
}

func TestContractDocNoCutValues(t *testing.T) {
	src, err := os.ReadFile(contractDocPath)
	if err != nil {
		t.Fatal(err)
	}
	if cut := cutPlainValues(string(src)); len(cut) > 0 {
		t.Fatalf("%s: unquoted values cut short by a ` #` comment on lines %v; double-quote them", contractDocPath, cut)
	}
}

func TestCutPlainValues(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want []int
	}{
		{"plain cut", "a:\n  description: needs a passkey (`Config.AdminPasskey`, #82). More.\n", []int{2}},
		{"anchor without space", "type: https://x/errors.md#conflict\n", nil},
		{"double-quoted", "description: \"needs (`x`, #82). More.\"\n", nil},
		{"single-quoted", "description: 'it''s #82'\n", nil},
		{"ref", "$ref: \"#/components/schemas/X\"\n", nil},
		{"block scalar", "description: |\n  see #82 here\n  and #83\nnext: ok\n", nil},
		{"after block", "description: >\n  see #82\nnext: cut #9\n", []int{3}},
		{"plain continuation", "description: first line\n  then #82 more\n", []int{2}},
		{"multi-line quoted", "description: \"first\n  then #82\"\nnext: ok\n", nil},
		{"comment line", "# a comment #82\n", nil},
		{"sequence item", "enum:\n  - a #b\n", []int{2}},
	}
	for _, c := range cases {
		got := cutPlainValues(c.src)
		if len(got) != len(c.want) || (len(got) > 0 && got[0] != c.want[0]) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
