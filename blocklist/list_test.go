package blocklist

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // the list's own hash
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/tomlawesome/gauntlet/internal/listsig"
)

var testBuilt = time.Date(2026, 10, 1, 3, 0, 0, 0, time.UTC)

// listHashes is 10,000 distinct synthetic hashes -- SHA-1 of seed-i --
// with SHA-1("password") among them, sorted. Synthetic on purpose: no
// real HIBP data is recorded in this repository.
//
// Memoised per seed: making 10,000 hashes under -race costs a tenth of
// a second, and dozens of cases want the same few sets. Callers get a
// copy, so a case that alters its set cannot alter another's.
func listHashes(seed string) []string {
	hashSetsMu.Lock()
	defer hashSetsMu.Unlock()
	if hs, ok := hashSets[seed]; ok {
		return slices.Clone(hs)
	}
	hs := makeHashes(seed)
	hashSets[seed] = hs
	return slices.Clone(hs)
}

var (
	hashSetsMu sync.Mutex
	hashSets   = map[string][]string{}
)

func makeHashes(seed string) []string {
	hs := []string{sha1Hex("password")}
	for i := 0; len(hs) < size; i++ {
		hs = append(hs, sha1Hex(fmt.Sprintf("%s-%d", seed, i)))
	}
	slices.Sort(hs)
	return hs
}

func sha1Hex(s string) string {
	h := sha1.Sum([]byte(s)) //nolint:gosec // the list's own hash
	return strings.ToUpper(hex.EncodeToString(h[:]))
}

// listFile is a well-formed list file around hashes, in the shape
// cmd/pwlist writes, with extra header lines appended to the header.
func listFile(built time.Time, hashes []string, extra ...string) []byte {
	var b strings.Builder
	b.WriteString(formatLine + "\n")
	b.WriteString("# source: synthetic test data\n")
	fmt.Fprintf(&b, "# built: %s\n", built.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "# count: %d\n", len(hashes))
	b.WriteString("# min-count: 1000\n")
	for _, e := range extra {
		b.WriteString(e + "\n")
	}
	for _, h := range hashes {
		b.WriteString(h + "\n")
	}
	return []byte(b.String())
}

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func sign(t *testing.T, data []byte, keys ...ed25519.PrivateKey) []byte {
	t.Helper()
	sig, err := listsig.Sign(data, keys)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func TestParseAcceptsAWellFormedList(t *testing.T) {
	l, err := Parse(listFile(testBuilt, listHashes("a"), "# attribution: test", "# future-key: ignored"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if l.Len() != size {
		t.Fatalf("Len = %d, want %d", l.Len(), size)
	}
	if !l.Built().Equal(testBuilt) {
		t.Fatalf("Built = %v, want %v", l.Built(), testBuilt)
	}
	if !l.Contains("password") {
		t.Fatal(`Contains("password") = false`)
	}
	// Exact, as HIBP is: a different spelling is a different entry.
	for _, pw := range []string{"Password", "password ", "", "correct horse battery staple"} {
		if l.Contains(pw) {
			t.Errorf("Contains(%q) = true", pw)
		}
	}
	// Every listed hash is found, first and last included.
	if !l.Contains("a-0") || !l.Contains(fmt.Sprintf("a-%d", size-2)) {
		t.Fatal("a listed password was not found")
	}
}

func TestParseRefuses(t *testing.T) {
	hs := listHashes("a")
	good := string(listFile(testBuilt, hs))
	header, body, _ := strings.Cut(good, hs[0]+"\n")
	body = hs[0] + "\n" + body

	swap := func(s, old, new string) string {
		if !strings.Contains(s, old) {
			t.Fatalf("test setup: %q not in file", old)
		}
		return strings.Replace(s, old, new, 1)
	}
	lower := slices.Clone(hs)
	lower[5] = strings.ToLower(lower[5])
	dup := slices.Clone(hs)
	dup[7] = dup[6]
	desc := slices.Clone(hs)
	desc[8], desc[9] = desc[9], desc[8]
	short := slices.Clone(hs)
	short[3] = short[3][:39]

	cases := map[string]string{
		"empty":                "",
		"no final newline":     strings.TrimSuffix(good, "\n"),
		"CRLF":                 strings.ReplaceAll(good, "\n", "\r\n"),
		"wrong format version": swap(good, "top10k/1", "top10k/2"),
		"no format line":       strings.SplitN(good, "\n", 2)[1],
		"format line twice":    swap(good, "# source:", formatLine+"\n# source:"),
		"no built":             swap(good, "# built: ", "# made: "),
		"built not RFC 3339":   swap(good, testBuilt.Format(time.RFC3339), "2026-10-01"),
		"no count":             swap(good, "# count: 10000\n", ""),
		"count wrong":          swap(good, "# count: 10000", "# count: 9999"),
		"header twice":         swap(good, "# min-count: 1000\n", "# min-count: 1000\n# min-count: 1\n"),
		"header without space": swap(good, "# min-count: 1000", "#min-count: 1000"),
		"header without colon": swap(good, "# min-count: 1000", "# min-count 1000"),
		"header empty key":     swap(good, "# min-count: 1000", "# : 1000"),
		"sample build":         swap(good, "# min-count: 1000", "# min-count: 1000\n# sample: 2048 of 1048576 prefixes"),
		"9,999 hashes":         header + strings.Join(hs[1:], "\n") + "\n",
		"10,001 hashes":        header + body + sha1Hex("zzz") + "\n",
		"lowercase hash":       string(listFile(testBuilt, lower)),
		"39-character hash":    string(listFile(testBuilt, short)),
		"duplicate hash":       string(listFile(testBuilt, dup)),
		"out of order":         string(listFile(testBuilt, desc)),
		"comment in body":      header + swap(body, hs[50]+"\n", hs[50]+"\n# late: header\n"),
		"blank line in body":   header + swap(body, hs[50]+"\n", hs[50]+"\n\n"),
		"counts kept":          header + swap(body, hs[0]+"\n", hs[0]+":123\n"),
	}
	for name, data := range cases {
		if l, err := Parse([]byte(data)); err == nil {
			t.Errorf("%s: Parse accepted it (Len %d)", name, l.Len())
		}
	}
	if _, err := Parse([]byte(good)); err != nil {
		t.Fatalf("the unmodified file must parse: %v", err)
	}
}

func TestEmptyListsBlockNothing(t *testing.T) {
	for name, l := range map[string]*List{"nil": nil, "zero": {}} {
		if l.Contains("password") || l.Len() != 0 || !l.Built().IsZero() {
			t.Errorf("%s list: Contains=%v Len=%d Built=%v", name, l.Contains("password"), l.Len(), l.Built())
		}
	}
}

// The copy compiled into this release. Until the first signed CI run it
// is the placeholder, and Embedded must be an empty list that blocks
// nothing; once the real list is committed it must verify against the
// committed keys and hold 10,000 hashes. The first real list arrives
// with the first signed run (scripts/update-blocklist.sh).
func TestEmbeddedCopy(t *testing.T) {
	_, placeholderErr := fs.Stat(embeddedFS, embeddedPlaceholder)
	e := Embedded()
	if e == nil {
		t.Fatal("Embedded() = nil")
	}
	if placeholderErr == nil {
		if e.Len() != 0 || e.Contains("password") || !e.Built().IsZero() {
			t.Fatalf("placeholder: Embedded() must be empty, got Len=%d Built=%v", e.Len(), e.Built())
		}
		return
	}
	data, err := fs.ReadFile(embeddedFS, embeddedList)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := fs.ReadFile(embeddedFS, embeddedSig)
	if err != nil {
		t.Fatalf("the embedded list has no signature beside it: %v", err)
	}
	ring, err := trustedKeys()
	if err != nil {
		t.Fatal(err)
	}
	if err := listsig.Verify(data, sig, ring); err != nil {
		t.Fatalf("the embedded list does not verify against blocklist/keys: %v", err)
	}
	if e.Len() != size || !e.Contains("password") {
		t.Fatalf("Embedded(): Len=%d, Contains(password)=%v", e.Len(), e.Contains("password"))
	}
}

func TestLoadEmbedded(t *testing.T) {
	good := listFile(testBuilt, listHashes("a"))
	cases := []struct {
		name    string
		files   fstest.MapFS
		wantLen int
		wantErr bool
	}{
		{"placeholder only", fstest.MapFS{embeddedPlaceholder: {Data: []byte("x")}}, 0, false},
		{"list only", fstest.MapFS{embeddedList: {Data: good}}, size, false},
		{"both", fstest.MapFS{embeddedPlaceholder: {Data: []byte("x")}, embeddedList: {Data: good}}, 0, true},
		{"neither", fstest.MapFS{"embedded/README": {Data: []byte("x")}}, 0, true},
		{"unparseable list", fstest.MapFS{embeddedList: {Data: []byte("nope\n")}}, 0, true},
	}
	for _, c := range cases {
		l, err := loadEmbedded(c.files)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: err = %v, wantErr %v", c.name, err, c.wantErr)
			continue
		}
		if err == nil && l.Len() != c.wantLen {
			t.Errorf("%s: Len = %d, want %d", c.name, l.Len(), c.wantLen)
		}
	}
}

func TestCommittedKeysParse(t *testing.T) {
	if _, err := trustedKeys(); err != nil {
		t.Fatalf("blocklist/keys: %v", err)
	}
}

// With no key committed -- this directory's state until the owner adds
// the first one -- verification must refuse everything; and a list
// signed by a key that is not committed is refused whatever is there.
func TestCommittedKeysRefuseAnUncommittedSigner(t *testing.T) {
	ring, err := trustedKeys()
	if err != nil {
		t.Fatal(err)
	}
	_, priv := newKey(t)
	data := listFile(testBuilt, listHashes("a"))
	err = listsig.Verify(data, sign(t, data, priv), ring)
	if len(ring) == 0 && !errors.Is(err, listsig.ErrNoKeys) {
		t.Fatalf("no committed keys: Verify = %v, want ErrNoKeys", err)
	}
	if len(ring) > 0 && !errors.Is(err, listsig.ErrUnknownKey) {
		t.Fatalf("Verify = %v, want ErrUnknownKey", err)
	}
}

func TestLoadKeys(t *testing.T) {
	aPub, _ := newKey(t)
	bPub, _ := newKey(t)
	aPEM, _ := listsig.MarshalPublicKey(aPub)
	bPEM, _ := listsig.MarshalPublicKey(bPub)

	ring, err := loadKeys(fstest.MapFS{
		"keys/a.pub":     {Data: aPEM},
		"keys/b.pub":     {Data: bPEM},
		"keys/README.md": {Data: []byte("not a key")},
		"keys/c.pub.bak": {Data: []byte("not a key")},
	}, "keys")
	if err != nil {
		t.Fatal(err)
	}
	if len(ring) != 2 || ring[listsig.KeyID(aPub)] == nil || ring[listsig.KeyID(bPub)] == nil {
		t.Fatalf("ring = %v", ring)
	}

	if _, err := loadKeys(fstest.MapFS{"keys/bad.pub": {Data: []byte("junk")}}, "keys"); err == nil {
		t.Fatal("a .pub that does not parse was accepted")
	}
	if _, err := loadKeys(fstest.MapFS{"keys/a.pub": {Data: aPEM}, "keys/a2.pub": {Data: aPEM}}, "keys"); err == nil {
		t.Fatal("the same key twice was accepted")
	}
	if _, err := loadKeys(fstest.MapFS{}, "keys"); err == nil {
		t.Fatal("a missing directory was accepted")
	}
	ring, err = loadKeys(fstest.MapFS{"keys/README.md": {Data: []byte("x")}}, "keys")
	if err != nil || len(ring) != 0 {
		t.Fatalf("README only: ring=%v err=%v", ring, err)
	}
}
