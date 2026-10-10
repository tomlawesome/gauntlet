package gauntlet

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// A name a person chooses counts characters, not bytes, and refuses
// U+FFFD (#90): docs/api/auth.yaml's maxLength counts characters, and a
// browser only sends U+FFFD when the text it was given was broken.

const charLimitMessage = "at most 64 characters of plain text"

// wideNames are 64-character names whose bytes run to 192 and 256.
var wideNames = []struct{ label, ch string }{
	{"three-byte CJK", "鍵"},
	{"four-byte emoji", "🔑"},
}

func TestTokenNameCountsCharactersNotBytes(t *testing.T) {
	if MaxTokenNameLen != 64 {
		t.Fatalf("MaxTokenNameLen = %d, this test is written for 64", MaxTokenNameLen)
	}
	for _, w := range wideNames {
		t.Run(w.label, func(t *testing.T) {
			s := newTestTokenStore(t)
			now := time.Now()

			name := strings.Repeat(w.ch, MaxTokenNameLen)
			_, tok, err := s.Create(name, TokenKindAPI, "", nil, now)
			if err != nil {
				t.Fatalf("Create with %d %s characters (%d bytes): %v, want it accepted", MaxTokenNameLen, w.label, len(name), err)
			}
			if tok.Name != name {
				t.Errorf("Name = %q, want the %d-character name untouched", tok.Name, MaxTokenNameLen)
			}

			_, _, err = s.Create(name+w.ch, TokenKindAPI, "", nil, now)
			if err != ErrTokenNameInvalid {
				t.Fatalf("Create with %d %s characters: err = %v, want ErrTokenNameInvalid", MaxTokenNameLen+1, w.label, err)
			}
			if n := len(s.List()); n != 1 {
				t.Errorf("store holds %d tokens, want only the accepted one", n)
			}
		})
	}
}

func TestTokenNameErrorSaysCharactersOfPlainText(t *testing.T) {
	s := newTestTokenStore(t)
	_, _, err := s.Create(strings.Repeat("n", MaxTokenNameLen+1), TokenKindAPI, "", nil, time.Now())
	if err != ErrTokenNameInvalid {
		t.Fatalf("Create with an over-long name: err = %v, want ErrTokenNameInvalid", err)
	}
	if !strings.Contains(err.Error(), charLimitMessage) {
		t.Errorf("error text = %q, want it to say %q", err.Error(), charLimitMessage)
	}
	if strings.Contains(err.Error(), "bytes") {
		t.Errorf("error text = %q still speaks of bytes", err.Error())
	}
}

func TestTokenNameRefusesTheReplacementCharacter(t *testing.T) {
	s := newTestTokenStore(t)
	for _, name := range []string{"\uFFFD", "ci\uFFFDrunner", "runner\uFFFD", "鍵\uFFFD鍵"} {
		if _, _, err := s.Create(name, TokenKindAPI, "", nil, time.Now()); err != ErrTokenNameInvalid {
			t.Errorf("Create(%q): err = %v, want ErrTokenNameInvalid", name, err)
		}
	}
	if n := len(s.List()); n != 0 {
		t.Errorf("store holds %d tokens, want none", n)
	}
}

func TestDeviceIDCountsCharactersNotBytes(t *testing.T) {
	if MaxDeviceIDLen != 64 {
		t.Fatalf("MaxDeviceIDLen = %d, this test is written for 64", MaxDeviceIDLen)
	}
	for _, w := range wideNames {
		t.Run(w.label, func(t *testing.T) {
			s := newTestTokenStore(t)
			now := time.Now()

			device := strings.Repeat(w.ch, MaxDeviceIDLen)
			_, tok, err := s.Create("router", TokenKindIngest, device, nil, now)
			if err != nil {
				t.Fatalf("Create with a device of %d %s characters (%d bytes): %v, want it accepted", MaxDeviceIDLen, w.label, len(device), err)
			}
			if tok.Device != device {
				t.Errorf("Device = %q, want the %d-character id untouched", tok.Device, MaxDeviceIDLen)
			}

			_, _, err = s.Create("router", TokenKindIngest, device+w.ch, nil, now)
			if err != ErrTokenDeviceInvalid {
				t.Fatalf("Create with a device of %d %s characters: err = %v, want ErrTokenDeviceInvalid", MaxDeviceIDLen+1, w.label, err)
			}
			if n := len(s.List()); n != 1 {
				t.Errorf("store holds %d tokens, want only the accepted one", n)
			}
		})
	}
}

func TestDeviceIDErrorSaysCharactersOfPlainText(t *testing.T) {
	s := newTestTokenStore(t)
	_, _, err := s.Create("router", TokenKindIngest, strings.Repeat("d", MaxDeviceIDLen+1), nil, time.Now())
	if err != ErrTokenDeviceInvalid {
		t.Fatalf("Create with an over-long device: err = %v, want ErrTokenDeviceInvalid", err)
	}
	if !strings.Contains(err.Error(), charLimitMessage) {
		t.Errorf("error text = %q, want it to say %q", err.Error(), charLimitMessage)
	}
	if strings.Contains(err.Error(), "bytes") {
		t.Errorf("error text = %q still speaks of bytes", err.Error())
	}
}

func TestDeviceIDRefusesTheReplacementCharacter(t *testing.T) {
	s := newTestTokenStore(t)
	for _, device := range []string{"\uFFFD", "router\uFFFD1", "router\uFFFD", "鍵\uFFFD鍵"} {
		if _, _, err := s.Create("router", TokenKindIngest, device, nil, time.Now()); err != ErrTokenDeviceInvalid {
			t.Errorf("Create with device %q: err = %v, want ErrTokenDeviceInvalid", device, err)
		}
	}
	if n := len(s.List()); n != 0 {
		t.Errorf("store holds %d tokens, want none", n)
	}
}

func TestValidateUsernameRefusesTheReplacementCharacter(t *testing.T) {
	for _, username := range []string{"\uFFFD", "ali\uFFFDce", "alice\uFFFD", "\uFFFDalice", "日本\uFFFD語"} {
		err := ValidateUsername(username)
		if !errors.Is(err, ErrUsernameInvalid) {
			t.Errorf("ValidateUsername(%q) = %v, want ErrUsernameInvalid", username, err)
		}
	}
}

func TestRegisterRefusesAUsernameHoldingTheReplacementCharacter(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.Register("ali\uFFFDce", "password-placeholder-1", time.Now()); !errors.Is(err, ErrUsernameInvalid) {
		t.Errorf("Register with U+FFFD in the username = %v, want ErrUsernameInvalid", err)
	}
	if s.Count() != 0 {
		t.Errorf("a refused Register created an account anyway (count=%d)", s.Count())
	}
}

// Guards: the length rule is unchanged and still names its own error,
// and a name of non-Latin letters within the limit is still welcome.
func TestValidateUsernameKeepsItsLengthRuleInCharacters(t *testing.T) {
	for _, tc := range []struct {
		label string
		in    string
		want  error
	}{
		{"64 Latin", strings.Repeat("a", 64), nil},
		{"65 Latin", strings.Repeat("a", 65), ErrUsernameLength},
		{"64 CJK", strings.Repeat("鍵", 64), nil},
		{"65 CJK", strings.Repeat("鍵", 65), ErrUsernameLength},
		{"64 emoji", strings.Repeat("🔑", 64), nil},
		{"65 emoji", strings.Repeat("🔑", 65), ErrUsernameLength},
		{"empty", "", ErrUsernameLength},
		{"Greek", "Ω-operator", nil},
		{"Arabic", "مفتاح", nil},
		{"Japanese", "日本語", nil},
	} {
		t.Run(tc.label, func(t *testing.T) {
			err := ValidateUsername(tc.in)
			if tc.want == nil && err != nil {
				t.Errorf("ValidateUsername(%d characters) = %v, want it accepted", len([]rune(tc.in)), err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("ValidateUsername(%d characters) = %v, want %v", len([]rune(tc.in)), err, tc.want)
			}
		})
	}
}

var replacementPasskeyNames = []struct{ label, name string }{
	{"alone", "\uFFFD"},
	{"at the start", "\uFFFDKey"},
	{"in the middle", "Yubi\uFFFDKey"},
	{"at the end", "YubiKey\uFFFD"},
}

func TestAddPasskeyRefusesTheReplacementCharacter(t *testing.T) {
	for _, tc := range replacementPasskeyNames {
		t.Run(tc.label, func(t *testing.T) {
			s, b, id := openHoldStore(t)
			saves := b.saves.Load()

			_, err := s.AddPasskey(id, testPasskey(1, tc.name))
			if !errors.Is(err, ErrPasskeyNameInvalid) {
				t.Fatalf("AddPasskey(%q) = %v, want ErrPasskeyNameInvalid", tc.name, err)
			}
			u, _ := s.Get(id)
			if len(u.Passkeys) != 0 {
				t.Errorf("a refused name still stored %d passkeys", len(u.Passkeys))
			}
			if got := b.saves.Load(); got != saves {
				t.Errorf("a refused name wrote to the backend (%d saves, was %d)", got, saves)
			}
		})
	}
}

func TestRenamePasskeyRefusesTheReplacementCharacter(t *testing.T) {
	for _, tc := range replacementPasskeyNames {
		t.Run(tc.label, func(t *testing.T) {
			s, b, id := openHoldStore(t)
			if _, err := s.AddPasskey(id, testPasskey(1, "original")); err != nil {
				t.Fatal(err)
			}
			saves := b.saves.Load()

			_, err := s.RenamePasskey(id, []byte{1}, tc.name)
			if !errors.Is(err, ErrPasskeyNameInvalid) {
				t.Fatalf("RenamePasskey(%q) = %v, want ErrPasskeyNameInvalid", tc.name, err)
			}
			u, _ := s.Get(id)
			if len(u.Passkeys) != 1 || u.Passkeys[0].Name != "original" {
				t.Errorf("passkeys after a refused rename = %+v, want the name unchanged", u.Passkeys)
			}
			if got := b.saves.Load(); got != saves {
				t.Errorf("a refused rename wrote to the backend (%d saves, was %d)", got, saves)
			}
		})
	}
}

// Guard: non-Latin names stay accepted by the store.
func TestPasskeyNamesOfOtherScriptsStayAccepted(t *testing.T) {
	s, _, id := openHoldStore(t)
	for i, name := range []string{"鍵", "مفتاح", "Clé de Zoë 🔑"} {
		got, err := s.AddPasskey(id, testPasskey(byte(i+1), name))
		if err != nil {
			t.Fatalf("AddPasskey(%q): %v", name, err)
		}
		if got.Name != name {
			t.Errorf("Name = %q, want %q", got.Name, name)
		}
	}
}
