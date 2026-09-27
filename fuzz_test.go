// Fuzz targets for the parsers that read attacker-influenced input
// directly, rather than data this package wrote itself: an encoded
// password hash, a username, a persisted store document, and a raw
// bearer token. Gauntlet issue #10.
package gauntlet

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/tomlawesome/gauntlet/persist"
	"golang.org/x/crypto/argon2"
)

// --- VerifyPassword ---

// fuzzArgon2CostTooHigh reports whether encoded declares Argon2id cost
// parameters above a fuzz-safe bound, using the same "m=,t=,p=" parse
// VerifyPassword itself uses (password.go). VerifyPassword places no
// upper bound on these attacker-influenced values before passing them to
// argon2.IDKey -- see this fuzz run's report for #10 -- so a corpus entry
// that declares a huge m or t would make the *fuzz process itself* OOM or
// hang rather than exercising the parser. This skip only protects the
// fuzz run; it does not change VerifyPassword's behaviour.
func fuzzArgon2CostTooHigh(encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 || parts[0] != "argon2id" {
		return false
	}
	var memory, iterations uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[2], "m=%d,t=%d,p=%d", &memory, &iterations, &threads); err != nil {
		return false
	}
	const maxMemoryKiB = 128 * 1024 // 128 MiB: 2x the real 64 MiB profile
	const maxIterations = 10
	return memory > maxMemoryKiB || iterations > maxIterations
}

// fuzzEncodeHash builds an encoded hash in HashPassword's format with a
// caller-fixed salt, rather than HashPassword's own crypto/rand salt.
// go's fuzzing engine re-executes this whole Fuzz function in separate
// worker processes, so a seed built from a randomly salted hash would
// embed one process's hash while later replays recompute the reference
// map with a different random salt -- comparing the two would report a
// false mismatch that is a bug in this test, not in VerifyPassword. A
// fixed salt keeps the reference deterministic across every replay.
func fuzzEncodeHash(password string, salt []byte) string {
	hash := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	return fmt.Sprintf("argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argon2Memory, argon2Time, argon2Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash))
}

func FuzzVerifyPassword(f *testing.F) {
	// Deliberately few passwords hashed for real (Argon2id at 64 MiB is
	// slow) -- this runs once at seed time, never per fuzz iteration.
	knownHashes := map[string]string{
		"correct-password": fuzzEncodeHash("correct-password", []byte("0123456789abcdef")),
		"":                 fuzzEncodeHash("", []byte("fedcba9876543210")),
		"unicode-🎉-pw":     fuzzEncodeHash("unicode-🎉-pw", []byte("saltsaltsaltsalt")),
	}

	f.Add("correct-password", knownHashes["correct-password"])
	f.Add("correct-password", "not-a-valid-hash")
	f.Add("", "")
	f.Add("x", "argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA")
	f.Add("password", "argon2id$v=19$m=999999999,t=999999999,p=255$c2FsdA$aGFzaA")
	f.Add("correct-password", knownHashes["correct-password"][:len(knownHashes["correct-password"])-1])
	f.Add("unicode-🎉-pw", knownHashes["unicode-🎉-pw"])

	f.Fuzz(func(t *testing.T, password, encoded string) {
		if fuzzArgon2CostTooHigh(encoded) {
			t.Skip("declared argon2 cost exceeds fuzz-safe bound")
		}
		got := VerifyPassword(password, encoded)
		if got && knownHashes[password] != encoded {
			t.Fatalf("VerifyPassword(%q, %q) = true, but that is not a hash this test produced for that password", password, encoded)
		}
	})
}

// --- ValidateUsername / ValidateLocalUsername ---

func seedFuzzUsernames(f *testing.F) {
	for _, u := range []string{
		"tom",
		"",
		strings.Repeat("a", 64),
		strings.Repeat("a", 65),
		" tom",
		"tom ",
		"tom\x00admin",
		"tom" + string(rune(0x202E)) + "admin", // U+202E RIGHT-TO-LEFT OVERRIDE
		"tom@example.com",
		strings.Repeat("🎉", 64),
		"tom@",
	} {
		f.Add(u)
	}
}

func FuzzValidateUsername(f *testing.F) {
	seedFuzzUsernames(f)
	f.Fuzz(func(t *testing.T, username string) {
		if err := ValidateUsername(username); err != nil {
			return
		}
		if username != strings.TrimSpace(username) {
			t.Fatalf("accepted username has leading/trailing whitespace: %q", username)
		}
		n := utf8.RuneCountInString(username)
		if n < minUsernameLength || n > maxUsernameLength {
			t.Fatalf("accepted username has out-of-range length %d: %q", n, username)
		}
		for _, r := range username {
			if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
				t.Fatalf("accepted username contains disallowed rune %U: %q", r, username)
			}
		}
	})
}

func FuzzValidateLocalUsername(f *testing.F) {
	seedFuzzUsernames(f)
	f.Fuzz(func(t *testing.T, username string) {
		if err := ValidateLocalUsername(username); err != nil {
			return
		}
		if err := ValidateUsername(username); err != nil {
			t.Fatalf("ValidateLocalUsername accepted %q but ValidateUsername rejects it: %v", username, err)
		}
		if strings.ContainsRune(username, '@') {
			t.Fatalf("ValidateLocalUsername accepted an email-shaped username: %q", username)
		}
	})
}

// --- OpenStore / OpenTokenStore over an arbitrary document ---

func FuzzOpenStore(f *testing.F) {
	for _, doc := range []string{
		`{"users":[]}`,
		`not json`,
		`{"users":[null]}`,
		`{"users":[{"id":"1","username":"tom"}]}`,
		``,
		`{"users":null}`,
		`[]`,
		`{}`,
	} {
		f.Add([]byte(doc))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		m := persist.NewMemory()
		if _, err := m.Save(context.Background(), data, 0); err != nil {
			t.Fatalf("priming memory backend: %v", err)
		}
		s, err := OpenStore(m, Options{})
		if err != nil {
			return
		}
		if s == nil {
			t.Fatal("OpenStore returned a nil store with a nil error")
		}
	})
}

func FuzzOpenTokenStore(f *testing.F) {
	for _, doc := range []string{
		`[]`,
		`not json`,
		`[null]`,
		`[{"id":"1","kind":"api","hashedValue":"deadbeef"}]`,
		``,
		`{}`,
	} {
		f.Add([]byte(doc))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		m := persist.NewMemory()
		if _, err := m.Save(context.Background(), data, 0); err != nil {
			t.Fatalf("priming memory backend: %v", err)
		}
		s, err := OpenTokenStore(m, TokenOptions{})
		if err != nil {
			return
		}
		if s == nil {
			t.Fatal("OpenTokenStore returned a nil store with a nil error")
		}
	})
}

// --- TokenStore.Authenticate ---

func FuzzTokenAuthenticate(f *testing.F) {
	s, err := OpenTokenStore(persist.NewMemory(), TokenOptions{})
	if err != nil {
		f.Fatalf("OpenTokenStore: %v", err)
	}
	now := time.Now()
	rawAPI, _, err := s.Create("api-token", TokenKindAPI, "", nil, now)
	if err != nil {
		f.Fatalf("Create(api): %v", err)
	}
	rawIngest, _, err := s.Create("ingest-token", TokenKindIngest, "device-1", nil, now)
	if err != nil {
		f.Fatalf("Create(ingest): %v", err)
	}

	f.Add(rawAPI, "api")
	f.Add(rawIngest, "ingest")
	f.Add(rawAPI, "ingest")
	f.Add(rawIngest, "api")
	f.Add("", "api")
	f.Add(rawAPI+"x", "api")
	f.Add(rawAPI[:len(rawAPI)-1], "api")

	f.Fuzz(func(t *testing.T, raw string, kindStr string) {
		kind := TokenKind(kindStr)
		tok, ok := s.Authenticate(raw, kind, time.Now())
		if !ok {
			return
		}
		switch raw {
		case rawAPI:
			if kind != TokenKindAPI || tok == nil || tok.Kind != TokenKindAPI {
				t.Fatalf("Authenticate matched the API token's raw value under kind %q", kindStr)
			}
		case rawIngest:
			if kind != TokenKindIngest || tok == nil || tok.Kind != TokenKindIngest {
				t.Fatalf("Authenticate matched the ingest token's raw value under kind %q", kindStr)
			}
		default:
			t.Fatalf("Authenticate succeeded for a raw value that was never issued: %q (kind %q)", raw, kindStr)
		}
	})
}
