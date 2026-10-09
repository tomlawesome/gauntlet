package seal

import (
	"encoding/base64"
	"strings"
	"testing"
)

type payload struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// otherPayload shares field names with payload but not their types, so a
// JSON-based codec cannot decode a payload into it.
type otherPayload struct {
	Name  []bool `json:"name"`
	Count string `json:"count"`
}

const b64urlAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

func mustCodec(t *testing.T) *Codec {
	t.Helper()
	c, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c == nil {
		t.Fatal("New returned a nil codec without an error")
	}
	return c
}

func mustSeal(t *testing.T, c *Codec, v any) string {
	t.Helper()
	s, err := c.Seal(v)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return s
}

func TestNewAndMustNewBuildCodecs(t *testing.T) {
	c := mustCodec(t)
	m := MustNew("test codec")
	if m == nil {
		t.Fatal("MustNew returned nil")
	}
	for name, codec := range map[string]*Codec{"New": c, "MustNew": m} {
		in := payload{Name: name, Count: 1}
		s := mustSeal(t, codec, in)
		var out payload
		if !codec.Open(s, &out) || out != in {
			t.Errorf("%s: codec does not open its own value (got %+v)", name, out)
		}
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	c := mustCodec(t)
	for _, in := range []payload{
		{},
		{Name: "alice", Count: 7},
		{Name: "snowman ☃ and quotes \" \\ ", Count: -1},
		{Name: strings.Repeat("x", 3000), Count: 1 << 30},
	} {
		s := mustSeal(t, c, in)
		var out payload
		if !c.Open(s, &out) {
			t.Fatalf("Open refused a value it sealed: %+v", in)
		}
		if out != in {
			t.Errorf("round trip: got %+v, want %+v", out, in)
		}
	}
}

func TestSealIsRandomised(t *testing.T) {
	c := mustCodec(t)
	in := payload{Name: "same", Count: 1}
	a, b := mustSeal(t, c, in), mustSeal(t, c, in)
	if a == b {
		t.Error("sealing the same value twice gave identical output; nonce is not fresh")
	}
}

func TestOpenRefusesOtherCodecsValue(t *testing.T) {
	a, b := mustCodec(t), mustCodec(t)
	s := mustSeal(t, a, payload{Name: "alice", Count: 1})
	var out payload
	if b.Open(s, &out) {
		t.Error("a value sealed by one codec opened under another codec")
	}
	if !a.Open(s, &out) {
		t.Error("control: the sealing codec should open its own value")
	}
}

func TestOpenRefusesFlippedByte(t *testing.T) {
	c := mustCodec(t)
	s := mustSeal(t, c, payload{Name: "alice", Count: 1})
	for _, pos := range []int{0, len(s) / 2, len(s) - 1} {
		repl := byte('A')
		if s[pos] == 'A' {
			repl = 'B'
		}
		bad := s[:pos] + string(repl) + s[pos+1:]
		var out payload
		if c.Open(bad, &out) {
			t.Errorf("Open accepted a value with the character at position %d changed", pos)
		}
	}
}

func TestOpenRefusesNonCanonicalBase64Spelling(t *testing.T) {
	c := mustCodec(t)
	found := 0
	// The last character carries spare bits only when the raw length is not
	// a multiple of three, so vary the payload length until one exists.
	for n := 0; n < 12; n++ {
		in := payload{Name: strings.Repeat("a", n), Count: n}
		s := mustSeal(t, c, in)
		want, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatalf("sealed value is not canonical base64url: %v", err)
		}
		last := s[len(s)-1]
		for i := 0; i < len(b64urlAlphabet); i++ {
			alt := b64urlAlphabet[i]
			if alt == last {
				continue
			}
			cand := s[:len(s)-1] + string(alt)
			// RawURLEncoding without Strict() ignores the spare bits.
			got, err := base64.RawURLEncoding.DecodeString(cand)
			if err != nil || string(got) != string(want) {
				continue
			}
			found++
			var out payload
			if c.Open(cand, &out) {
				t.Errorf("Open accepted a non-canonical spelling of a sealed value (payload length %d)", n)
			}
			if !c.Open(s, &out) {
				t.Errorf("control: the canonical spelling should open (payload length %d)", n)
			}
			break
		}
	}
	if found == 0 {
		t.Fatal("test could not construct any non-canonical spelling; adjust the payload sizes")
	}
}

func TestSealOutputIsUnpaddedBase64URL(t *testing.T) {
	c := mustCodec(t)
	for n := 0; n < 12; n++ {
		s := mustSeal(t, c, payload{Name: strings.Repeat("é", n), Count: n})
		if s == "" {
			t.Fatal("empty sealed value")
		}
		if strings.Contains(s, "=") {
			t.Errorf("sealed value contains padding: %q", s)
		}
		for _, r := range s {
			if !strings.ContainsRune(b64urlAlphabet, r) {
				t.Errorf("sealed value contains %q outside the base64url alphabet: %q", r, s)
				break
			}
		}
	}
}

func TestOpenRefusesEmptyShortAndJunk(t *testing.T) {
	c := mustCodec(t)
	for name, v := range map[string]string{
		"empty":       "",
		"one char":    "A",
		"short":       "AAAA",
		"short valid": "AAAAAAAAAAAAAAAA",
		"junk":        "not a sealed value!",
		"padding":     "AAAA====",
		"std base64":  "+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/",
		"whitespace":  " \n\t ",
		"nul":         "\x00\x00\x00",
	} {
		var out payload
		if c.Open(v, &out) {
			t.Errorf("%s: Open accepted %q", name, v)
		}
	}
}

func TestOpenRefusesMismatchedType(t *testing.T) {
	c := mustCodec(t)
	s := mustSeal(t, c, payload{Name: "alice", Count: 1})
	var wrong otherPayload
	if c.Open(s, &wrong) {
		t.Error("Open accepted a value into a mismatched type")
	}
	var num int
	if c.Open(s, &num) {
		t.Error("Open accepted a struct into an int")
	}
}

// Go's base64 decoder skips '\r' and '\n' even when strict, so a sealed
// value with a line break inserted would open as the same bytes: two
// strings for one sealed value.
func TestOpenRefusesLineBreaks(t *testing.T) {
	c := mustCodec(t)
	in := payload{Name: "alice", Count: 1}
	s := mustSeal(t, c, in)
	var out payload
	if !c.Open(s, &out) || out != in {
		t.Fatalf("control: the original should open (got %+v)", out)
	}
	for _, br := range []string{"\n", "\r", "\r\n"} {
		for where, pos := range map[string]int{"start": 0, "middle": len(s) / 2, "end": len(s)} {
			bad := s[:pos] + br + s[pos:]
			var got payload
			if c.Open(bad, &got) {
				t.Errorf("Open accepted a sealed value with %q inserted at the %s", br, where)
			}
		}
	}
}
