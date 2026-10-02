package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(context.Background(), args, &out, &errb)
	return code, out.String(), errb.String()
}

// writeList puts a well-formed, unsigned list and its checksum in dir,
// as `build` leaves them, and returns the list's path.
func writeList(t *testing.T, dir string, sample string) string {
	t.Helper()
	var hs []string
	for _, e := range variedCorpus(12).all[:defaultTop] {
		hs = append(hs, e.Hash)
	}
	slices.Sort(hs)
	data := formatList(hs, testNow, 1000, 12000, sample)
	path := filepath.Join(dir, "top10k.txt")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".sha256", []byte(sha256Line(data, "top10k.txt")), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// keypair makes a key with `keygen` and returns the private and public
// key directories, kept apart as they are in production.
func keypair(t *testing.T, name string) (privDir, pubDir string) {
	t.Helper()
	dir := t.TempDir()
	if code, _, stderr := runCLI(t, "keygen", "--out", dir, "--name", name); code != 0 {
		t.Fatalf("keygen: %d %s", code, stderr)
	}
	privDir, pubDir = filepath.Join(dir, "priv"), filepath.Join(dir, "pub")
	for _, d := range []string{privDir, pubDir} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Rename(filepath.Join(dir, name+".key"), filepath.Join(privDir, name+".key")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, name+".pub"), filepath.Join(pubDir, name+".pub")); err != nil {
		t.Fatal(err)
	}
	return privDir, pubDir
}

func TestKeygenWritesAPairAndNeverOverwrites(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	code, stdout, stderr := runCLI(t, "keygen", "--out", dir, "--name", "pwlist-2026")
	if code != 0 {
		t.Fatalf("keygen: %d %s", code, stderr)
	}
	if !strings.Contains(stdout, "key id ") {
		t.Fatalf("stdout: %s", stdout)
	}
	for name, mode := range map[string]os.FileMode{"pwlist-2026.key": 0o600, "pwlist-2026.pub": 0o644} {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != mode {
			t.Errorf("%s mode %v, want %v", name, fi.Mode().Perm(), mode)
		}
	}
	before, _ := os.ReadFile(filepath.Join(dir, "pwlist-2026.key"))
	if code, _, _ := runCLI(t, "keygen", "--out", dir, "--name", "pwlist-2026"); code != 1 {
		t.Fatalf("second keygen exit %d, want 1", code)
	}
	after, _ := os.ReadFile(filepath.Join(dir, "pwlist-2026.key"))
	if !bytes.Equal(before, after) {
		t.Fatal("keygen overwrote a private key")
	}

	// The private key already exists under another name's public half:
	// a failed .pub write must not leave a lone new .key behind.
	if err := os.WriteFile(filepath.Join(dir, "other.pub"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := runCLI(t, "keygen", "--out", dir, "--name", "other"); code != 1 {
		t.Fatal("keygen succeeded over an existing .pub")
	}
	if _, err := os.Stat(filepath.Join(dir, "other.key")); !os.IsNotExist(err) {
		t.Fatal("a lone private key was left behind")
	}
}

func TestSignThenVerify(t *testing.T) {
	t.Parallel()
	privDir, pubDir := keypair(t, "a")
	list := writeList(t, t.TempDir(), "")
	code, stdout, stderr := runCLI(t, "sign", "--keys", privDir, "--in", list)
	if code != 0 {
		t.Fatalf("sign: %d %s", code, stderr)
	}
	if !strings.Contains(stdout, "signed ") {
		t.Fatalf("sign stdout: %s", stdout)
	}
	code, stdout, stderr = runCLI(t, "verify", "--keys", pubDir, "--in", list)
	if code != 0 {
		t.Fatalf("verify: %d %s", code, stderr)
	}
	if !strings.Contains(stdout, "is good: 10000 hashes, built "+testNow.Format(time.RFC3339)) {
		t.Fatalf("verify stdout: %s", stdout)
	}
}

// Two private keys in the directory: both sign, and a verifier knowing
// either one accepts -- the rotation path.
func TestSignWithEveryKeyForRotation(t *testing.T) {
	t.Parallel()
	privA, pubA := keypair(t, "old")
	privB, pubB := keypair(t, "new")
	if err := os.Rename(filepath.Join(privB, "new.key"), filepath.Join(privA, "new.key")); err != nil {
		t.Fatal(err)
	}
	list := writeList(t, t.TempDir(), "")
	if code, _, stderr := runCLI(t, "sign", "--keys", privA, "--in", list); code != 0 {
		t.Fatalf("sign: %s", stderr)
	}
	sig, _ := os.ReadFile(list + ".sig")
	if strings.Count(string(sig), "\n") != 2 {
		t.Fatalf("want two signature lines:\n%s", sig)
	}
	for _, pub := range []string{pubA, pubB} {
		if code, _, stderr := runCLI(t, "verify", "--keys", pub, "--in", list); code != 0 {
			t.Fatalf("verify with %s: %s", pub, stderr)
		}
	}
}

func TestVerifyRefuses(t *testing.T) {
	t.Parallel()
	cases := map[string]func(t *testing.T, list, pubDir string){
		"altered list": func(t *testing.T, list, _ string) {
			b, _ := os.ReadFile(list)
			b[len(b)-2] ^= 1
			_ = os.WriteFile(list, b, 0o644)
		},
		"altered list and checksum": func(t *testing.T, list, _ string) {
			b, _ := os.ReadFile(list)
			b[len(b)-2] = '0'
			if b[len(b)-3] == '0' {
				b[len(b)-3] = '1'
			}
			_ = os.WriteFile(list, b, 0o644)
			sum := sha256.Sum256(b)
			_ = os.WriteFile(list+".sha256", []byte(hex.EncodeToString(sum[:])+"  top10k.txt\n"), 0o644)
		},
		"checksum names another file": func(t *testing.T, list, _ string) {
			b, _ := os.ReadFile(list + ".sha256")
			_ = os.WriteFile(list+".sha256", bytes.Replace(b, []byte("top10k.txt"), []byte("other.txt"), 1), 0o644)
		},
		"no checksum":  func(t *testing.T, list, _ string) { _ = os.Remove(list + ".sha256") },
		"no signature": func(t *testing.T, list, _ string) { _ = os.Remove(list + ".sig") },
		"no list":      func(t *testing.T, list, _ string) { _ = os.Remove(list) },
		"unknown signer": func(t *testing.T, _, pubDir string) {
			_ = os.Remove(filepath.Join(pubDir, "a.pub"))
			_, other := keypair(t, "b")
			_ = os.Rename(filepath.Join(other, "b.pub"), filepath.Join(pubDir, "b.pub"))
		},
		"no trusted keys": func(t *testing.T, _, pubDir string) { _ = os.Remove(filepath.Join(pubDir, "a.pub")) },
		"broken .pub file": func(t *testing.T, _, pubDir string) {
			_ = os.WriteFile(filepath.Join(pubDir, "z.pub"), []byte("junk"), 0o644)
		},
	}
	for name, spoil := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			privDir, pubDir := keypair(t, "a")
			list := writeList(t, t.TempDir(), "")
			if code, _, stderr := runCLI(t, "sign", "--keys", privDir, "--in", list); code != 0 {
				t.Fatalf("sign: %s", stderr)
			}
			spoil(t, list, pubDir)
			if code, _, _ := runCLI(t, "verify", "--keys", pubDir, "--in", list); code != 1 {
				t.Fatalf("verify exit %d, want 1", code)
			}
		})
	}
}

func TestSignRefuses(t *testing.T) {
	t.Parallel()
	t.Run("a sample", func(t *testing.T) {
		privDir, _ := keypair(t, "a")
		list := writeList(t, t.TempDir(), "12 of 48 prefixes; not for publication")
		if code, _, stderr := runCLI(t, "sign", "--keys", privDir, "--in", list); code != 1 || !strings.Contains(stderr, "sample") {
			t.Fatalf("sign of a sample: %d %s", code, stderr)
		}
		if _, err := os.Stat(list + ".sig"); !os.IsNotExist(err) {
			t.Fatal("a sample was signed")
		}
	})
	t.Run("a checksum mismatch", func(t *testing.T) {
		privDir, _ := keypair(t, "a")
		list := writeList(t, t.TempDir(), "")
		_ = os.WriteFile(list+".sha256", []byte(strings.Repeat("0", 64)+"  top10k.txt\n"), 0o644)
		if code, _, _ := runCLI(t, "sign", "--keys", privDir, "--in", list); code != 1 {
			t.Fatal("signed a list whose checksum does not match")
		}
	})
	t.Run("no keys", func(t *testing.T) {
		list := writeList(t, t.TempDir(), "")
		if code, _, stderr := runCLI(t, "sign", "--keys", t.TempDir(), "--in", list); code != 1 || !strings.Contains(stderr, "no *.key") {
			t.Fatalf("sign with no keys: %d %s", code, stderr)
		}
	})
	t.Run("a broken key", func(t *testing.T) {
		dir := t.TempDir()
		_ = os.WriteFile(filepath.Join(dir, "x.key"), []byte("junk"), 0o600)
		list := writeList(t, t.TempDir(), "")
		if code, _, _ := runCLI(t, "sign", "--keys", dir, "--in", list); code != 1 {
			t.Fatal("signed with a broken key")
		}
	})
}

func TestUsageErrors(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{},
		{"frobnicate"},
		{"build", "--prefixes", "0"},
		{"build", "--prefixes", "1048577"},
		{"build", "--concurrency", "0"},
		{"build", "stray"},
		{"build", "--no-such-flag"},
		{"sign"},
		{"verify"},
		{"keygen", "--out", "x"},
		{"keygen", "--out", "x", "--name", "Bad Name"},
		{"keygen", "--name", "ok"},
		{"sign", "-h"},
	} {
		if code, _, _ := runCLI(t, args...); code != 2 {
			t.Errorf("pwlist %v: exit %d, want 2", args, code)
		}
	}
}

// The real `build` wiring, against a fake range API, as the CI sample
// path runs it: 12 prefixes meet the full run's total bar scaled to
// their share, and the output is marked as a sample.
func TestBuildCommandWiring(t *testing.T) {
	t.Parallel()
	srv := newRangeServer(t, variedCorpus(12))
	dir := t.TempDir()
	out := filepath.Join(dir, "top10k.txt")
	code, _, stderr := runCLI(t, "build", "--base-url", srv.URL+"/range/", "--prefixes", "12",
		"--concurrency", "4", "--out", out, "--checkpoint", filepath.Join(dir, "cp.json"))
	if code != 0 {
		t.Fatalf("build: exit %d\n%s", code, stderr)
	}
	if srv.totalHits() != 12 {
		t.Fatalf("build made %d requests, want 12", srv.totalHits())
	}
	srv.mu.Lock()
	ua := srv.requests[0].Header.Get("User-Agent")
	srv.mu.Unlock()
	if ua != "gauntlet-pwlist/dev (+gitlab.tomlawson.io/ai/gauntlet)" {
		t.Fatalf("User-Agent %q", ua)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "\n# sample: 12 of 1048576 prefixes; not for publication\n") {
		t.Fatal("the sample is not marked")
	}
}
