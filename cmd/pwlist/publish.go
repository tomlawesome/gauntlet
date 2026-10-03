package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/tomlawesome/gauntlet/blocklist"
)

// The GitHub release copy (owner, 2026-10-02, on #52): the GitLab
// project is private, so applications fetch the list from releases on
// the public mirror, github.com/tomlawesome/gauntlet. GitLab stays the
// first home -- blocklist:publish uploads to its package registry first
// and only then copies the same signed files here.
//
// Two releases per run. `pwned-top10k-current` is the one
// blocklist.DefaultURL reads; its three files are replaced each run.
// `pwned-top10k-<YYYY.MM.DD>` is the run's own and is never rewritten:
// a file already there is left alone if it is the same file (by the
// SHA-256 digest GitHub reports, or by downloading it where it reports
// none) and is an error if it is not, so a retried job finishes the job instead of
// failing on what its first attempt already did.
//
// Neither release is marked "latest", so the repository's latest
// release stays the newest gauntlet version. A tag created here points
// at --target on GitHub; nothing on GitLab carries it, and the mirror
// sync never fetches from GitHub.
//
// The token is read from a file and sent only in the Authorization
// header; it is never logged, never in an error, never on a command
// line. It needs write access to this repository's releases and
// nothing else (a fine-grained token, "Contents: read and write", on
// tomlawesome/gauntlet only).

const (
	githubAPI     = "https://api.github.com"
	githubTimeout = 2 * time.Minute
	// maxTokenFile bounds the token file: a GitHub token is under 100
	// bytes, and reading an unbounded file named by a CI variable is a
	// needless risk.
	maxTokenFile = 1024
)

// publishFiles is the upload order within a release. The checksum goes
// last: a Refresher fetches it first and stops when it is unchanged,
// so until it changes no reader pairs the new list with the old
// checksum. Replacing a file deletes the old one before uploading the
// new, so a reader can briefly get a 404; it logs once and tries again
// at its next interval.
var publishFiles = []string{"", ".sig", ".sha256"}

var tagName = regexp.MustCompile(`^pwned-top10k-[a-z0-9.]+$`)

type github struct {
	api, repo, token, userAgent string
	client                      *http.Client
}

type ghAsset struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	Digest string `json:"digest"` // "sha256:<hex>"; GitHub sends it for assets uploaded since mid-2025
}

// same reports whether a holds exactly data: by its SHA-256 digest
// when GitHub gives one, and otherwise by downloading it and comparing
// bytes. Size never decides: every list is 10,000 hashes and a header
// of near-fixed width, so a corrected list is usually the same size as
// the wrong one it must not be mistaken for.
func (g *github) same(ctx context.Context, a ghAsset, data []byte) (bool, error) {
	if a.Digest != "" {
		sum := sha256.Sum256(data)
		return a.Digest == "sha256:"+hex.EncodeToString(sum[:]), nil
	}
	got, err := g.download(ctx, a.ID, int64(len(data))+1)
	if err != nil {
		return false, fmt.Errorf("download %s to compare it: %w", a.Name, err)
	}
	return bytes.Equal(got, data), nil
}

type ghRelease struct {
	ID        int64     `json:"id"`
	UploadURL string    `json:"upload_url"`
	Assets    []ghAsset `json:"assets"`
}

func cmdPublishGitHub(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlags("publish-github", stderr)
	repo := fs.String("repo", "tomlawesome/gauntlet", "the GitHub repository, OWNER/NAME")
	tokenFile := fs.String("token-file", "", "file holding the GitHub token (read, never printed)")
	in := fs.String("in", "top10k.txt", "the signed list; FILE.sha256 and FILE.sig go with it")
	current := fs.String("current-tag", "pwned-top10k-current", "the release whose files are replaced each run")
	dated := fs.String("dated-tag", "", "this run's own release, never rewritten, e.g. pwned-top10k-2026.10.02")
	target := fs.String("target", "dev", "the branch or commit on GitHub a newly created tag points at")
	api := fs.String("api", githubAPI, "the GitHub API base URL")
	if err := parse(fs, args, stderr); err != nil {
		return err
	}
	if *tokenFile == "" || !tagName.MatchString(*current) || !tagName.MatchString(*dated) || *current == *dated ||
		!strings.Contains(*repo, "/") || *target == "" {
		_, _ = fmt.Fprintln(stderr, "pwlist publish-github: --token-file is required; --current-tag and --dated-tag must be two different pwned-top10k-* tags")
		return errUsage
	}
	// Publish only what verifies as a list: the same check `sign`
	// makes, so a sample or a damaged file never reaches the mirror.
	// The signature itself was checked against the committed keys by
	// `verify` earlier in the job.
	data, err := checkedList(*in)
	if err != nil {
		return err
	}
	l, _ := blocklist.Parse(data)
	if _, err := os.Stat(*in + ".sig"); err != nil {
		return err
	}
	token, err := readToken(*tokenFile)
	if err != nil {
		return err
	}
	gh := &github{
		api: strings.TrimSuffix(*api, "/"), repo: *repo, token: token,
		userAgent: "gauntlet-pwlist/" + version + " (+gitlab.tomlawson.io/ai/gauntlet)",
		client:    &http.Client{Timeout: githubTimeout},
	}
	built := l.Built().Format(time.RFC3339)
	for _, rel := range []struct {
		tag, name string
		replace   bool
	}{
		{*dated, "Common-password list " + strings.TrimPrefix(*dated, "pwned-top10k-"), false},
		{*current, "Common-password list (current)", true},
	} {
		if err := gh.publish(ctx, rel.tag, rel.name, *target, built, *in, rel.replace, stdout); err != nil {
			return fmt.Errorf("release %s: %w", rel.tag, err)
		}
	}
	return nil
}

func readToken(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("token file: %w", err)
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, maxTokenFile+1))
	if err != nil {
		return "", fmt.Errorf("token file: %w", err)
	}
	if len(raw) > maxTokenFile {
		return "", fmt.Errorf("token file %s is over %d bytes; it should hold one token", path, maxTokenFile)
	}
	token := strings.TrimSpace(string(raw))
	if token == "" || strings.ContainsAny(token, " \t\r\n") {
		return "", fmt.Errorf("token file %s must hold exactly one token", path)
	}
	return token, nil
}

// publish makes sure release tag exists and holds the list's three
// files, replacing them when replace is set.
func (g *github) publish(ctx context.Context, tag, name, target, built, in string, replace bool, stdout io.Writer) error {
	rel, err := g.release(ctx, tag)
	if err != nil {
		return err
	}
	if rel == nil {
		body := "gauntlet's common-password list: the SHA-1 hashes of the 10,000 most prevalent " +
			"Pwned Passwords, built " + built + ". Data from haveibeenpwned.com (no licence terms; " +
			"attribution voluntary). Signed in GitLab CI; verify with `pwlist verify`. See ADR-0007."
		if rel, err = g.createRelease(ctx, tag, name, target, body); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(stdout, "pwlist publish-github: created release %s\n", tag)
	}
	for _, ext := range publishFiles {
		path := in + ext
		assetName := filepath.Base(path)
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var existing *ghAsset
		for i := range rel.Assets {
			if rel.Assets[i].Name == assetName {
				existing = &rel.Assets[i]
			}
		}
		if existing != nil && !replace {
			same, err := g.same(ctx, *existing, data)
			if err != nil {
				return err
			}
			if !same {
				return fmt.Errorf("%s already holds a different %s; a dated release is never rewritten", tag, assetName)
			}
			_, _ = fmt.Fprintf(stdout, "pwlist publish-github: %s/%s already there\n", tag, assetName)
			continue
		}
		if existing != nil {
			if err := g.do(ctx, http.MethodDelete, fmt.Sprintf("%s/repos/%s/releases/assets/%d", g.api, g.repo, existing.ID), "", nil, http.StatusNoContent, nil); err != nil {
				return fmt.Errorf("delete the old %s: %w", assetName, err)
			}
		}
		if err := g.upload(ctx, rel, assetName, data); err != nil {
			return fmt.Errorf("upload %s: %w", assetName, err)
		}
		_, _ = fmt.Fprintf(stdout, "pwlist publish-github: uploaded %s/%s\n", tag, assetName)
	}
	return nil
}

// release returns the release for tag, or nil if there is none.
func (g *github) release(ctx context.Context, tag string) (*ghRelease, error) {
	var rel ghRelease
	err := g.do(ctx, http.MethodGet, fmt.Sprintf("%s/repos/%s/releases/tags/%s", g.api, g.repo, url.PathEscape(tag)), "", nil, http.StatusOK, &rel)
	var se statusError
	if errors.As(err, &se) && se.code == http.StatusNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &rel, nil
}

func (g *github) createRelease(ctx context.Context, tag, name, target, body string) (*ghRelease, error) {
	req, err := json.Marshal(map[string]any{
		"tag_name":         tag,
		"target_commitish": target,
		"name":             name,
		"body":             body,
		"make_latest":      "false",
	})
	if err != nil {
		return nil, err
	}
	var rel ghRelease
	if err := g.do(ctx, http.MethodPost, fmt.Sprintf("%s/repos/%s/releases", g.api, g.repo), "application/json", req, http.StatusCreated, &rel); err != nil {
		return nil, err
	}
	return &rel, nil
}

func (g *github) upload(ctx context.Context, rel *ghRelease, name string, data []byte) error {
	// upload_url is a URI template: ".../assets{?name,label}".
	base, _, _ := strings.Cut(rel.UploadURL, "{")
	u, err := url.Parse(base)
	if err != nil || u.Scheme == "" {
		return fmt.Errorf("release has no usable upload_url: %q", rel.UploadURL)
	}
	u.RawQuery = url.Values{"name": {name}}.Encode()
	return g.do(ctx, http.MethodPost, u.String(), "application/octet-stream", data, http.StatusCreated, nil)
}

// download fetches an asset's bytes, reading at most limit of them:
// GitHub answers with a redirect to its download host, which the client
// follows without the Authorization header.
func (g *github) download(ctx context.Context, id, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/repos/%s/releases/assets/%d", g.api, g.repo, id), nil)
	if err != nil {
		return nil, err
	}
	g.header(req, "application/octet-stream")
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", req.URL.Redacted(), resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

type statusError struct {
	code int
	msg  string
}

func (e statusError) Error() string { return e.msg }

// do sends one GitHub API request and decodes a JSON answer into out.
// A status other than want is an error quoting GitHub's message, which
// never contains the token.
func (g *github) do(ctx context.Context, method, u, contentType string, body []byte, want int, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	g.header(req, "application/vnd.github+json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := g.client.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, req.URL.Redacted(), err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != want {
		msg := strings.TrimSpace(string(raw))
		if len(msg) > 300 {
			msg = msg[:300] + "..."
		}
		return statusError{resp.StatusCode, fmt.Sprintf("%s %s: %s: %s", method, req.URL.Redacted(), resp.Status, msg)}
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("%s %s: decode the answer: %w", method, req.URL.Redacted(), err)
		}
	}
	return nil
}

func (g *github) header(req *http.Request, accept string) {
	req.Header.Set("Authorization", "Bearer "+g.token)
	req.Header.Set("Accept", accept)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", g.userAgent)
}
