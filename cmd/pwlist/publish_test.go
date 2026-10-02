package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

const fakeToken = "test-token-not-a-credential"

// fakeGitHub is the slice of the GitHub releases API publish-github
// uses: get a release by tag, create one, delete an asset, upload one.
type fakeGitHub struct {
	*httptest.Server
	t        *testing.T
	mu       sync.Mutex
	nextID   int64
	releases map[string]*fakeRelease // by tag
	created  []map[string]any        // create-release request bodies
	log      []string                // "METHOD path" in order
	failOn   string                  // "METHOD path-prefix" answered 500
	uploads  int
	failNth  int // answer the Nth upload with 500
}

type fakeRelease struct {
	id     int64
	assets map[string]ghAsset // by name
	data   map[string][]byte
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	t.Helper()
	g := &fakeGitHub{t: t, nextID: 100, releases: map[string]*fakeRelease{}}
	g.Server = httptest.NewServer(http.HandlerFunc(g.serve))
	t.Cleanup(g.Close)
	return g
}

func (g *fakeGitHub) serve(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.log = append(g.log, r.Method+" "+r.URL.Path)
	if r.Header.Get("Authorization") != "Bearer "+fakeToken {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if r.Header.Get("X-GitHub-Api-Version") == "" || r.Header.Get("User-Agent") == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if g.failOn != "" && strings.HasPrefix(r.Method+" "+r.URL.Path, g.failOn) {
		http.Error(w, `{"message":"boom"}`, http.StatusInternalServerError)
		return
	}
	const repo = "/repos/tomlawesome/gauntlet"
	p := r.URL.Path
	switch {
	case r.Method == http.MethodGet && strings.HasPrefix(p, repo+"/releases/tags/"):
		rel, ok := g.releases[strings.TrimPrefix(p, repo+"/releases/tags/")]
		if !ok {
			http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
			return
		}
		g.writeRelease(w, http.StatusOK, rel)
	case r.Method == http.MethodPost && p == repo+"/releases":
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		g.created = append(g.created, req)
		g.nextID++
		rel := &fakeRelease{id: g.nextID, assets: map[string]ghAsset{}, data: map[string][]byte{}}
		g.releases[req["tag_name"].(string)] = rel
		g.writeRelease(w, http.StatusCreated, rel)
	case r.Method == http.MethodDelete && strings.HasPrefix(p, repo+"/releases/assets/"):
		id, _ := strconv.ParseInt(strings.TrimPrefix(p, repo+"/releases/assets/"), 10, 64)
		for _, rel := range g.releases {
			for name, a := range rel.assets {
				if a.ID == id {
					delete(rel.assets, name)
					delete(rel.data, name)
					w.WriteHeader(http.StatusNoContent)
					return
				}
			}
		}
		w.WriteHeader(http.StatusNotFound)
	case r.Method == http.MethodPost && strings.HasPrefix(p, "/uploads"+repo+"/releases/"):
		g.uploads++
		if g.uploads == g.failNth {
			http.Error(w, `{"message":"upload failed"}`, http.StatusBadGateway)
			return
		}
		id, _ := strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(p, "/uploads"+repo+"/releases/"), "/assets"), 10, 64)
		name := r.URL.Query().Get("name")
		if r.Header.Get("Content-Type") != "application/octet-stream" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		for _, rel := range g.releases {
			if rel.id == id {
				if _, dup := rel.assets[name]; dup {
					http.Error(w, `{"message":"already_exists"}`, http.StatusUnprocessableEntity)
					return
				}
				data, _ := io.ReadAll(r.Body)
				g.nextID++
				sum := sha256.Sum256(data)
				rel.assets[name] = ghAsset{ID: g.nextID, Name: name, Size: int64(len(data)), Digest: "sha256:" + hex.EncodeToString(sum[:])}
				rel.data[name] = data
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(`{}`))
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (g *fakeGitHub) writeRelease(w http.ResponseWriter, code int, rel *fakeRelease) {
	out := ghRelease{
		ID:        rel.id,
		UploadURL: fmt.Sprintf("%s/uploads/repos/tomlawesome/gauntlet/releases/%d/assets{?name,label}", g.URL, rel.id),
	}
	for _, a := range rel.assets {
		out.Assets = append(out.Assets, a)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(out)
}

// signedListDir is a signed list, its checksum and signature, as
// blocklist:sign leaves them, plus a token file.
func signedListDir(t *testing.T) (list, tokenFile string) {
	t.Helper()
	privDir, _ := keypair(t, "a")
	dir := t.TempDir()
	list = writeList(t, dir, "")
	if code, _, stderr := runCLI(t, "sign", "--keys", privDir, "--in", list); code != 0 {
		t.Fatalf("sign: %s", stderr)
	}
	tokenFile = filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte(fakeToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return list, tokenFile
}

func publishArgs(g *fakeGitHub, list, tokenFile, dated string) []string {
	return []string{"publish-github", "--api", g.URL, "--token-file", tokenFile, "--in", list, "--dated-tag", dated}
}

func TestPublishGitHubCreatesBothReleases(t *testing.T) {
	t.Parallel()
	g := newFakeGitHub(t)
	list, tok := signedListDir(t)
	code, stdout, stderr := runCLI(t, publishArgs(g, list, tok, "pwned-top10k-2026.10.02")...)
	if code != 0 {
		t.Fatalf("publish-github: %d %s", code, stderr)
	}
	for _, tag := range []string{"pwned-top10k-2026.10.02", "pwned-top10k-current"} {
		rel := g.releases[tag]
		if rel == nil {
			t.Fatalf("no release %s", tag)
		}
		for _, ext := range []string{"", ".sig", ".sha256"} {
			want, _ := os.ReadFile(list + ext)
			if got := rel.data["top10k.txt"+ext]; string(got) != string(want) {
				t.Errorf("%s: top10k.txt%s not uploaded as signed", tag, ext)
			}
		}
	}
	for _, req := range g.created {
		if req["make_latest"] != "false" || req["target_commitish"] != "dev" {
			t.Errorf("create request %v: must not be latest, and must target dev", req)
		}
	}
	if strings.Contains(stdout+stderr, fakeToken) {
		t.Fatal("the token was printed")
	}
	// Within a release the checksum is uploaded last.
	var uploads []string
	for _, l := range g.log {
		if strings.HasPrefix(l, "POST /uploads") {
			uploads = append(uploads, l)
		}
	}
	if len(uploads) != 6 {
		t.Fatalf("uploads: %v", uploads)
	}
}

// A second run replaces current's files and leaves the earlier dated
// release alone.
func TestPublishGitHubReplacesCurrentOnly(t *testing.T) {
	t.Parallel()
	g := newFakeGitHub(t)
	list, tok := signedListDir(t)
	if code, _, stderr := runCLI(t, publishArgs(g, list, tok, "pwned-top10k-2026.10.02")...); code != 0 {
		t.Fatal(stderr)
	}
	oldDated := g.releases["pwned-top10k-2026.10.02"].assets["top10k.txt"].ID
	oldCurrent := g.releases["pwned-top10k-current"].assets["top10k.txt"].ID

	// Next month's list: different bytes.
	b, _ := os.ReadFile(list)
	b = []byte(strings.Replace(string(b), "# built: 2026-10-02T04:30:00Z", "# built: 2026-11-02T04:30:00Z", 1))
	if err := os.WriteFile(list, b, 0o644); err != nil {
		t.Fatal(err)
	}
	writeSum(t, list)
	if code, _, stderr := runCLI(t, publishArgs(g, list, tok, "pwned-top10k-2026.11.02")...); code != 0 {
		t.Fatal(stderr)
	}
	if g.releases["pwned-top10k-2026.10.02"].assets["top10k.txt"].ID != oldDated {
		t.Fatal("an earlier dated release was rewritten")
	}
	cur := g.releases["pwned-top10k-current"]
	if cur.assets["top10k.txt"].ID == oldCurrent || !strings.Contains(string(cur.data["top10k.txt"]), "2026-11-02") {
		t.Fatal("current's list was not replaced")
	}
	if len(cur.assets) != 3 {
		t.Fatalf("current holds %d files", len(cur.assets))
	}
}

// A retried job finds its dated release partly or wholly done and
// finishes it; a dated release holding different files is an error.
func TestPublishGitHubDatedReleaseIsNeverRewritten(t *testing.T) {
	t.Parallel()
	g := newFakeGitHub(t)
	list, tok := signedListDir(t)
	g.failNth = 2 // the dated release's .sig, after its list
	code, _, _ := runCLI(t, publishArgs(g, list, tok, "pwned-top10k-2026.10.02")...)
	if code != 1 {
		t.Fatal("the failed upload was not reported")
	}
	g.failNth = 0
	if code, stdout, stderr := runCLI(t, publishArgs(g, list, tok, "pwned-top10k-2026.10.02")...); code != 0 {
		t.Fatalf("retry: %s", stderr)
	} else if !strings.Contains(stdout, "already there") {
		t.Fatalf("retry did not reuse what was uploaded:\n%s", stdout)
	}

	// The same dated tag with a different list.
	b, _ := os.ReadFile(list)
	b = []byte(strings.Replace(string(b), "# min-count: 1000", "# min-count: 1001", 1))
	_ = os.WriteFile(list, b, 0o644)
	writeSum(t, list)
	code, _, stderr := runCLI(t, publishArgs(g, list, tok, "pwned-top10k-2026.10.02")...)
	if code != 1 || !strings.Contains(stderr, "never rewritten") {
		t.Fatalf("rewrote a dated release: %d %s", code, stderr)
	}
}

func TestPublishGitHubRefuses(t *testing.T) {
	t.Parallel()
	g := newFakeGitHub(t)
	list, tok := signedListDir(t)

	empty := filepath.Join(t.TempDir(), "empty")
	_ = os.WriteFile(empty, []byte("\n"), 0o600)
	two := filepath.Join(t.TempDir(), "two")
	_ = os.WriteFile(two, []byte("one two\n"), 0o600)
	big := filepath.Join(t.TempDir(), "big")
	_ = os.WriteFile(big, []byte(strings.Repeat("x", maxTokenFile+1)), 0o600)
	wrong := filepath.Join(t.TempDir(), "wrong")
	_ = os.WriteFile(wrong, []byte("not-the-token\n"), 0o600)

	for name, args := range map[string][]string{
		"missing token file": publishArgs(g, list, filepath.Join(t.TempDir(), "nope"), "pwned-top10k-2026.10.02"),
		"empty token file":   publishArgs(g, list, empty, "pwned-top10k-2026.10.02"),
		"two tokens":         publishArgs(g, list, two, "pwned-top10k-2026.10.02"),
		"oversized file":     publishArgs(g, list, big, "pwned-top10k-2026.10.02"),
		"rejected token":     publishArgs(g, list, wrong, "pwned-top10k-2026.10.02"),
		"no list":            publishArgs(g, list+".missing", tok, "pwned-top10k-2026.10.02"),
	} {
		code, stdout, stderr := runCLI(t, args...)
		if code != 1 {
			t.Errorf("%s: exit %d, want 1 (%s)", name, code, stderr)
		}
		if strings.Contains(stdout+stderr, fakeToken) || strings.Contains(stdout+stderr, "not-the-token") {
			t.Errorf("%s: the token was printed", name)
		}
	}
	for name, args := range map[string][]string{
		"no dated tag":    {"publish-github", "--token-file", tok, "--in", list},
		"bad dated tag":   {"publish-github", "--token-file", tok, "--in", list, "--dated-tag", "v1.0.0"},
		"same tag twice":  {"publish-github", "--token-file", tok, "--in", list, "--dated-tag", "pwned-top10k-current"},
		"no token file":   {"publish-github", "--in", list, "--dated-tag", "pwned-top10k-2026.10.02"},
		"repo without /":  {"publish-github", "--token-file", tok, "--in", list, "--dated-tag", "pwned-top10k-2026.10.02", "--repo", "gauntlet"},
		"stray arguments": {"publish-github", "--token-file", tok, "--dated-tag", "pwned-top10k-2026.10.02", "extra"},
	} {
		if code, _, _ := runCLI(t, args...); code != 2 {
			t.Errorf("%s: exit %d, want 2", name, code)
		}
	}
	// A sample is never published.
	sampleDir := t.TempDir()
	sample := writeList(t, sampleDir, "12 of 48 prefixes; not for publication")
	_ = os.WriteFile(sample+".sig", []byte("x\n"), 0o644)
	if code, _, _ := runCLI(t, publishArgs(g, sample, tok, "pwned-top10k-2026.10.02")...); code != 1 {
		t.Error("published a sample")
	}
	if len(g.releases) != 0 {
		t.Fatalf("a refused run created releases: %v", g.releases)
	}
}

func TestPublishGitHubReportsGitHubErrors(t *testing.T) {
	t.Parallel()
	g := newFakeGitHub(t)
	list, tok := signedListDir(t)
	g.failOn = "POST /repos/tomlawesome/gauntlet/releases"
	code, _, stderr := runCLI(t, publishArgs(g, list, tok, "pwned-top10k-2026.10.02")...)
	if code != 1 || !strings.Contains(stderr, "500") || !strings.Contains(stderr, "boom") {
		t.Fatalf("exit %d, stderr %s", code, stderr)
	}
	g.failOn = "GET /repos/tomlawesome/gauntlet/releases/tags/"
	if code, _, _ := runCLI(t, publishArgs(g, list, tok, "pwned-top10k-2026.10.02")...); code != 1 {
		t.Fatal("a failed lookup was not reported")
	}
}

func TestAssetSame(t *testing.T) {
	t.Parallel()
	data := []byte("abc")
	sum := sha256.Sum256(data)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	if !(ghAsset{Digest: digest, Size: 99}).same(data) {
		t.Error("a matching digest must win over the size")
	}
	if (ghAsset{Digest: digest, Size: 3}).same([]byte("abd")) {
		t.Error("same size, different bytes, matched")
	}
	if !(ghAsset{Size: 3}).same(data) || (ghAsset{Size: 4}).same(data) {
		t.Error("without a digest, size decides")
	}
}

func writeSum(t *testing.T, list string) {
	t.Helper()
	b, err := os.ReadFile(list)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(list+".sha256", []byte(sha256Line(b, filepath.Base(list))), 0o644); err != nil {
		t.Fatal(err)
	}
}
