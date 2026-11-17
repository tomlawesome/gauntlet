package gauntlet

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"log/slog"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet/persist"
)

// setupCodeShape is the displayed form: four groups of four from the
// reset-code alphabet.
var setupCodeShape = regexp.MustCompile(`^[A-Z2-9]{4}(-[A-Z2-9]{4}){3}$`)

// openEmptyWithHook opens an empty store whose setup code is captured
// through Options.OnSetupCode, the way a test (or an app printing the
// code its own way) gets hold of it.
func openEmptyWithHook(t *testing.T, m *persist.Memory) (*Store, string) {
	t.Helper()
	var code string
	s, err := OpenStore(m, Options{OnSetupCode: SetupCodeFunc(func(c string) { code = c })})
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	if code == "" {
		t.Fatal("opening an empty persisted store announced no setup code")
	}
	return s, code
}

func TestSetupCodeAnnouncedOnEmptyStoreAndChecked(t *testing.T) {
	s, code := openEmptyWithHook(t, persist.NewMemory())
	if !setupCodeShape.MatchString(code) {
		t.Fatalf("setup code %q is not xxxx-xxxx-xxxx-xxxx over the reset-code alphabet", code)
	}

	if err := s.CheckSetupCode(code); err != nil {
		t.Errorf("CheckSetupCode(announced code) = %v, want nil", err)
	}
	// Typed without dashes, or in lower case, is the same code.
	if err := s.CheckSetupCode(strings.ToLower(strings.ReplaceAll(code, "-", ""))); err != nil {
		t.Errorf("CheckSetupCode(lower case, no dashes) = %v, want nil", err)
	}
	assertWrongSetupCodesRefused(t, s, code)
	if s.Count() != 0 {
		t.Errorf("checking a code created %d accounts", s.Count())
	}
}

// TestSetupCodeEndingInARefusesItsNearMiss is #40: the near-miss above
// once replaced the code's last character with "A", which is the code
// itself whenever the real one already ends in A (one open in 32), so
// the test failed at random. A code ending in A is installed here
// directly, so that case runs every time.
func TestSetupCodeEndingInARefusesItsNearMiss(t *testing.T) {
	s, _ := openEmptyWithHook(t, persist.NewMemory())
	const canonical = "BCDEFGHJKLMNPQRA"
	sum := sha256.Sum256([]byte(canonical))
	s.mu.Lock()
	s.setupCodeHash = sum[:]
	s.mu.Unlock()
	code := FormatResetCode(canonical)
	if err := s.CheckSetupCode(code); err != nil {
		t.Fatalf("CheckSetupCode(the installed code %q) = %v, want nil", code, err)
	}
	assertWrongSetupCodesRefused(t, s, code)
}

// assertWrongSetupCodesRefused checks codes that are not code -- empty,
// a fixed wrong one, a near miss in the last character, one character
// too many -- are all refused.
func assertWrongSetupCodesRefused(t *testing.T, s *Store, code string) {
	t.Helper()
	last := "A"
	if strings.HasSuffix(code, "A") {
		last = "B"
	}
	nearMiss := code[:len(code)-1] + last
	for _, wrong := range []string{"", "AAAA-AAAA-AAAA-AAAA", nearMiss, code + "A"} {
		if wrong == code {
			t.Fatalf("test bug: the wrong code %q is the real one", wrong)
		}
		if err := s.CheckSetupCode(wrong); !errors.Is(err, ErrSetupCodeInvalid) {
			t.Errorf("CheckSetupCode(%q) = %v, want ErrSetupCodeInvalid", wrong, err)
		}
	}
}

func TestSetupCodeDiffersPerOpen(t *testing.T) {
	_, a := openEmptyWithHook(t, persist.NewMemory())
	_, b := openEmptyWithHook(t, persist.NewMemory())
	if a == b {
		t.Fatalf("two stores announced the same setup code %q", a)
	}
}

func TestSetupCodeLoggedWhenNoHook(t *testing.T) {
	var logs bytes.Buffer
	s, err := OpenStore(persist.NewMemory(), Options{Log: slog.New(slog.NewTextHandler(&logs, nil))})
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	line := logs.String()
	if !strings.Contains(line, "level=WARN") || !strings.Contains(line, "setup code") {
		t.Fatalf("expected one WARN line naming the setup code, got %q", line)
	}
	code := regexp.MustCompile(`[A-Z2-9]{4}(?:-[A-Z2-9]{4}){3}`).FindString(line)
	if code == "" {
		t.Fatalf("no code in the log line %q", line)
	}
	if err := s.CheckSetupCode(code); err != nil {
		t.Errorf("CheckSetupCode(logged code) = %v, want nil", err)
	}
}

func TestSetupCodeHookReplacesLog(t *testing.T) {
	var logs bytes.Buffer
	_, err := OpenStore(persist.NewMemory(), Options{
		Log:         slog.New(slog.NewTextHandler(&logs, nil)),
		OnSetupCode: SetupCodeFunc(func(string) {}),
	})
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	if logs.Len() != 0 {
		t.Fatalf("a store with OnSetupCode still logged the code: %q", logs.String())
	}
}

func TestSetupCodeInertOnceAnAccountExists(t *testing.T) {
	s, code := openEmptyWithHook(t, persist.NewMemory())
	if _, err := s.Register("admin", "password-placeholder-345", time.Now()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := s.CheckSetupCode(code); !errors.Is(err, ErrRegistrationClosed) {
		t.Errorf("CheckSetupCode after the first account = %v, want ErrRegistrationClosed", err)
	}
}

func TestNoSetupCodeWhenAccountsExistAtOpen(t *testing.T) {
	m := persist.NewMemory()
	primeMemory(t, m, `{"users":[{"id":"a","username":"admin","role":"admin","passwordHash":"x"}]}`)
	called := false
	s, err := OpenStore(m, Options{OnSetupCode: SetupCodeFunc(func(string) { called = true })})
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	if called {
		t.Error("a store that opened with accounts announced a setup code")
	}
	if err := s.CheckSetupCode("AAAA-AAAA-AAAA-AAAA"); !errors.Is(err, ErrRegistrationClosed) {
		t.Errorf("CheckSetupCode = %v, want ErrRegistrationClosed", err)
	}
}

func TestNoSetupCodeWithoutPersistence(t *testing.T) {
	called := false
	s, err := OpenStore(nil, Options{OnSetupCode: SetupCodeFunc(func(string) { called = true })})
	if err != nil {
		t.Fatalf("OpenStore(nil): %v", err)
	}
	if called {
		t.Error("an unpersisted store announced a setup code; nothing can be set up on it")
	}
	if err := s.CheckSetupCode("AAAA-AAAA-AAAA-AAAA"); !errors.Is(err, ErrNotPersisted) {
		t.Errorf("CheckSetupCode = %v, want ErrNotPersisted", err)
	}
}

// A document another process wrote decides the code's fate on reload:
// accounts retire it, an emptied document issues a fresh one.
func TestSetupCodeFollowsReloadedDocument(t *testing.T) {
	m := persist.NewMemory()
	var codes []string
	s, err := OpenStore(m, Options{OnSetupCode: SetupCodeFunc(func(c string) { codes = append(codes, c) })})
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	if len(codes) != 1 {
		t.Fatalf("announced %d codes at open, want 1", len(codes))
	}

	other, err := OpenStore(m, Options{OnSetupCode: SetupCodeFunc(func(string) {})})
	if err != nil {
		t.Fatalf("OpenStore (other process): %v", err)
	}
	if _, err := other.Register("admin", "password-placeholder-345", time.Now()); err != nil {
		t.Fatalf("Register in the other process: %v", err)
	}
	s.reloadIfStale()
	if err := s.CheckSetupCode(codes[0]); !errors.Is(err, ErrRegistrationClosed) {
		t.Errorf("after reloading an account, CheckSetupCode = %v, want ErrRegistrationClosed", err)
	}

	// The other process empties the document again (a restore of an
	// empty file, say): setup is required again, under a new code.
	version := s.version
	// seq (#59) is set ahead of what s has already seen (alice's
	// account, seq 1), or this empty document -- a legitimate reset --
	// would itself be refused as a rollback.
	if _, err := m.Save(t.Context(), []byte(`{"version":1,"seq":2,"users":[]}`), version); err != nil {
		t.Fatalf("emptying the document: %v", err)
	}
	s.reloadIfStale()
	if len(codes) != 2 {
		t.Fatalf("announced %d codes after reloading an empty document, want 2", len(codes))
	}
	if codes[1] == codes[0] {
		t.Error("the re-issued code is the old one")
	}
	if err := s.CheckSetupCode(codes[0]); !errors.Is(err, ErrSetupCodeInvalid) {
		t.Errorf("old code after re-issue: %v, want ErrSetupCodeInvalid", err)
	}
	if err := s.CheckSetupCode(codes[1]); err != nil {
		t.Errorf("new code: %v, want nil", err)
	}
}

func TestFindOrCreateOIDCUserRefusesOnEmptyStore(t *testing.T) {
	s, _ := openEmptyWithHook(t, persist.NewMemory())
	u, created, err := s.FindOrCreateOIDCUser("https://idp.example", "sub-1", "alice", time.Now())
	if !errors.Is(err, ErrSetupRequired) {
		t.Fatalf("FindOrCreateOIDCUser on an empty store = (%v, %v, %v), want ErrSetupRequired", u, created, err)
	}
	if created || u != nil || s.Count() != 0 {
		t.Errorf("refusal still provisioned: created=%v user=%v count=%d", created, u, s.Count())
	}
}
