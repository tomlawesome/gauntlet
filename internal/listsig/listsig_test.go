package listsig

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
)

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func ring(t *testing.T, keys ...ed25519.PublicKey) Keyring {
	t.Helper()
	r, err := NewKeyring(keys...)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestKeyIDIsSixteenHexOfThePublicKeysSHA256(t *testing.T) {
	// SHA-256 of 32 zero bytes is 66687aadf862bd776c8fc18b8e9f8e20...
	if got := KeyID(make(ed25519.PublicKey, 32)); got != "66687aadf862bd77" {
		t.Fatalf("KeyID(zero key) = %q", got)
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv := newKey(t)
	data := []byte("some list\n")
	sig, err := Sign(data, []ed25519.PrivateKey{priv})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(sig), KeyID(pub)+" ") {
		t.Fatalf("signature line does not start with the key id: %q", sig)
	}
	if err := Verify(data, sig, ring(t, pub)); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifyRefusesTamperedData(t *testing.T) {
	pub, priv := newKey(t)
	sig, _ := Sign([]byte("original\n"), []ed25519.PrivateKey{priv})
	if err := Verify([]byte("Original\n"), sig, ring(t, pub)); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("Verify(tampered) = %v, want ErrBadSignature", err)
	}
}

func TestVerifyWithNoKeysRefusesEverything(t *testing.T) {
	_, priv := newKey(t)
	data := []byte("x\n")
	sig, _ := Sign(data, []ed25519.PrivateKey{priv})
	for _, r := range []Keyring{nil, {}} {
		if err := Verify(data, sig, r); !errors.Is(err, ErrNoKeys) {
			t.Fatalf("Verify with empty ring = %v, want ErrNoKeys", err)
		}
	}
}

func TestVerifyRefusesAnUnknownKey(t *testing.T) {
	_, priv := newKey(t)
	other, _ := newKey(t)
	data := []byte("x\n")
	sig, _ := Sign(data, []ed25519.PrivateKey{priv})
	if err := Verify(data, sig, ring(t, other)); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("Verify(unknown signer) = %v, want ErrUnknownKey", err)
	}
}

// A rotation: the file is signed by the old and the new key. A build
// knowing either one accepts it; the unknown line is skipped.
func TestVerifyMultiSignatureRotation(t *testing.T) {
	oldPub, oldPriv := newKey(t)
	newPub, newPriv := newKey(t)
	data := []byte("rotating\n")
	sig, err := Sign(data, []ed25519.PrivateKey{oldPriv, newPriv})
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(sig), "\n"); n != 2 {
		t.Fatalf("want two lines, got %d: %q", n, sig)
	}
	for name, r := range map[string]Keyring{
		"old only": ring(t, oldPub),
		"new only": ring(t, newPub),
		"both":     ring(t, oldPub, newPub),
	} {
		if err := Verify(data, sig, r); err != nil {
			t.Errorf("%s: Verify = %v", name, err)
		}
	}
}

// Two trusted keys, one line good and one bad: the signing job signs
// with every key it holds, so a bad line from a trusted key means the
// file was altered.
func TestVerifyRefusesOneBadLineFromATrustedKey(t *testing.T) {
	aPub, aPriv := newKey(t)
	bPub, bPriv := newKey(t)
	data := []byte("x\n")
	good, _ := Sign(data, []ed25519.PrivateKey{aPriv})
	bad, _ := Sign([]byte("something else\n"), []ed25519.PrivateKey{bPriv})
	sig := append(good, bad...)
	if err := Verify(data, sig, ring(t, aPub, bPub)); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("Verify = %v, want ErrBadSignature", err)
	}
}

func TestVerifyRefusesMalformedFiles(t *testing.T) {
	pub, priv := newKey(t)
	data := []byte("x\n")
	good, _ := Sign(data, []ed25519.PrivateKey{priv})
	line := strings.TrimSuffix(string(good), "\n")
	id, b64, _ := strings.Cut(line, " ")
	cases := map[string]string{
		"empty":                  "",
		"no trailing newline":    line,
		"blank line":             line + "\n\n",
		"no space":               id + b64 + "\n",
		"uppercase id":           strings.ToUpper(id) + " " + b64 + "\n",
		"short id":               id[:15] + " " + b64 + "\n",
		"not base64":             id + " !!!!\n",
		"short signature":        id + " " + base64.StdEncoding.EncodeToString([]byte("short")) + "\n",
		"repeated key id":        line + "\n" + line + "\n",
		"over the size limit":    line + "\n" + strings.Repeat("0", MaxSignatureFile) + "\n",
		"trailing space":         line + " \n",
		"carriage return":        line + "\r\n",
		"unpadded base64 strict": id + " " + strings.TrimRight(b64, "=") + "\n",
	}
	for name, sig := range cases {
		if err := Verify(data, []byte(sig), ring(t, pub)); err == nil {
			t.Errorf("%s: Verify accepted %q", name, sig)
		}
	}
}

func TestSignRefusesNoKeysAndDuplicateKeys(t *testing.T) {
	if _, err := Sign([]byte("x"), nil); err == nil {
		t.Fatal("Sign with no keys succeeded")
	}
	_, priv := newKey(t)
	if _, err := Sign([]byte("x"), []ed25519.PrivateKey{priv, priv}); err == nil {
		t.Fatal("Sign with the same key twice succeeded")
	}
}

func TestSignIsDeterministicAcrossKeyOrder(t *testing.T) {
	_, a := newKey(t)
	_, b := newKey(t)
	s1, _ := Sign([]byte("x"), []ed25519.PrivateKey{a, b})
	s2, _ := Sign([]byte("x"), []ed25519.PrivateKey{b, a})
	if string(s1) != string(s2) {
		t.Fatalf("key order changed the file:\n%s\n%s", s1, s2)
	}
}

func TestNewKeyringRefusesBadKeys(t *testing.T) {
	pub, _ := newKey(t)
	if _, err := NewKeyring(pub, pub); err == nil {
		t.Fatal("NewKeyring accepted the same key twice")
	}
	if _, err := NewKeyring(ed25519.PublicKey{1, 2, 3}); err == nil {
		t.Fatal("NewKeyring accepted a 3-byte key")
	}
}

func TestPEMRoundTrips(t *testing.T) {
	pub, priv := newKey(t)
	pubPEM, err := MarshalPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	gotPub, err := ParsePublicKey(pubPEM)
	if err != nil || !gotPub.Equal(pub) {
		t.Fatalf("public round trip: %v", err)
	}
	privPEM, err := MarshalPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	gotPriv, err := ParsePrivateKey(privPEM)
	if err != nil || !gotPriv.Equal(priv) {
		t.Fatalf("private round trip: %v", err)
	}
}

func TestParseKeysRefusesTheWrongThing(t *testing.T) {
	pub, priv := newKey(t)
	pubPEM, _ := MarshalPublicKey(pub)
	privPEM, _ := MarshalPrivateKey(priv)

	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecPubDER, _ := x509.MarshalPKIXPublicKey(&ec.PublicKey)
	ecPrivDER, _ := x509.MarshalPKCS8PrivateKey(ec)
	ecPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: ecPubDER})
	ecPriv := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ecPrivDER})

	for name, data := range map[string][]byte{
		"not PEM":        []byte("hello"),
		"private as pub": privPEM,
		"two keys":       append(append([]byte{}, pubPEM...), pubPEM...),
		"ECDSA key":      ecPub,
		"garbage in PEM": pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("junk")}),
	} {
		if _, err := ParsePublicKey(data); err == nil {
			t.Errorf("ParsePublicKey(%s) succeeded", name)
		}
	}
	for name, data := range map[string][]byte{
		"not PEM":        []byte("hello"),
		"public as priv": pubPEM,
		"two keys":       append(append([]byte{}, privPEM...), privPEM...),
		"ECDSA key":      ecPriv,
		"garbage in PEM": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("junk")}),
	} {
		if _, err := ParsePrivateKey(data); err == nil {
			t.Errorf("ParsePrivateKey(%s) succeeded", name)
		}
	}
}
