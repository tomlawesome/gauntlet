// Command pwlist builds, signs and verifies gauntlet's common-password
// list (#52, ADR-0007): the SHA-1 hashes of the 10,000 most prevalent
// passwords in Have I Been Pwned's Pwned Passwords corpus, the list
// package blocklist embeds and refreshes.
//
//	pwlist build  [--out top10k.txt] [--checkpoint FILE] [--prefixes N] [--concurrency N] [--base-url URL]
//	pwlist sign   --keys DIR [--in top10k.txt]
//	pwlist verify --keys DIR [--in top10k.txt]
//	pwlist keygen --out DIR --name NAME
//	pwlist publish-github --token-file FILE --dated-tag pwned-top10k-YYYY.MM.DD [--in top10k.txt]
//
// `build` reads the whole corpus through the k-anonymity range API --
// all 1,048,576 five-hex-digit prefixes, in order, 32 requests at a
// time -- keeps the 10,000 hashes seen most often, and writes them with
// a SHA-256 beside them (top10k.txt.sha256). It runs in the scheduled
// `blocklist:build` CI job; with --prefixes below the full range it is
// a sample run whose output says so and which nothing will sign or
// accept. `sign` signs a list with every private key (*.key) in a
// directory, writing top10k.txt.sig; it runs in `blocklist:sign` on the
// runner that holds the key. `verify` checks a list's checksum, format
// and signature against the public keys (*.pub) in a directory, the
// same checks a Refresher makes. `publish-github` copies a signed list
// to the GitHub releases applications download from (publish.go).
// `keygen` makes a new Ed25519 key pair for the owner, once per key.
//
// Standard library only, like the package it feeds: no third-party
// code runs on the signing runner.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"syscall"
	"time"

	"github.com/tomlawesome/gauntlet/blocklist"
	"github.com/tomlawesome/gauntlet/internal/listsig"
)

// version is set at build time (-ldflags "-X main.version=...") from
// the repository's VERSION file, and goes into the User-Agent so HIBP
// can tell which release is calling.
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

const usage = `usage:
  pwlist build  [--out top10k.txt] [--checkpoint FILE] [--prefixes N] [--concurrency N] [--base-url URL]
  pwlist sign   --keys DIR [--in top10k.txt]
  pwlist verify --keys DIR [--in top10k.txt]
  pwlist keygen --out DIR --name NAME
  pwlist publish-github --token-file FILE --dated-tag pwned-top10k-YYYY.MM.DD [--in top10k.txt] [--keys DIR] [--current-tag T] [--repo O/R] [--target REF]
`

// run is main without the process: exit code 0 on success, 1 on a
// failure, 2 on a usage error.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
	var cmd func(context.Context, []string, io.Writer, io.Writer) error
	switch args[0] {
	case "build":
		cmd = cmdBuild
	case "sign":
		cmd = cmdSign
	case "verify":
		cmd = cmdVerify
	case "keygen":
		cmd = cmdKeygen
	case "publish-github":
		cmd = cmdPublishGitHub
	default:
		_, _ = fmt.Fprintf(stderr, "pwlist: unknown command %q\n%s", args[0], usage)
		return 2
	}
	if err := cmd(ctx, args[1:], stdout, stderr); err != nil {
		if errors.Is(err, errUsage) || errors.Is(err, flag.ErrHelp) {
			return 2
		}
		_, _ = fmt.Fprintf(stderr, "pwlist %s: %v\n", args[0], err)
		return 1
	}
	return 0
}

var errUsage = errors.New("usage")

func newFlags(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("pwlist "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

// parse parses args and refuses stray positional arguments, which are
// otherwise silently ignored.
func parse(fs *flag.FlagSet, args []string, stderr io.Writer) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return errUsage // the flag package has already printed why
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintf(stderr, "%s: unexpected argument %q\n", fs.Name(), fs.Arg(0))
		return errUsage
	}
	return nil
}

func cmdBuild(ctx context.Context, args []string, _, stderr io.Writer) error {
	fs := newFlags("build", stderr)
	out := fs.String("out", "top10k.txt", "where to write the list; its SHA-256 goes beside it as `FILE`.sha256")
	checkpoint := fs.String("checkpoint", "", "save progress after each chunk to this file, and resume from it (ignored if older than 24 h)")
	prefixes := fs.Int("prefixes", totalPrefixes, "walk only the first N prefixes: a sample run, never publishable")
	concurrency := fs.Int("concurrency", defaultConcurrency, "requests in flight at once")
	baseURL := fs.String("base-url", defaultBaseURL, "the range API, ending in /")
	if err := parse(fs, args, stderr); err != nil {
		return err
	}
	if *prefixes < 1 || *prefixes > totalPrefixes {
		_, _ = fmt.Fprintf(stderr, "pwlist build: --prefixes must be 1-%d\n", totalPrefixes)
		return errUsage
	}
	if *concurrency < 1 || *concurrency > 256 {
		_, _ = fmt.Fprintln(stderr, "pwlist build: --concurrency must be 1-256")
		return errUsage
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConnsPerHost = *concurrency // keep every worker's connection alive between requests
	b := &builder{
		baseURL:     *baseURL,
		client:      &http.Client{Transport: transport},
		userAgent:   "gauntlet-pwlist/" + version + " (+gitlab.tomlawson.io/ai/gauntlet)",
		prefixes:    *prefixes,
		fullRange:   totalPrefixes,
		chunkSize:   defaultChunkSize,
		concurrency: *concurrency,
		top:         defaultTop,
		minTotal:    defaultMinTotal,
		minCount:    defaultMinCount,
		checkpoint:  *checkpoint,
		out:         *out,
		log:         stderr,
		now:         time.Now,
		sleep:       sleepCtx,
	}
	return b.run(ctx)
}

func cmdSign(_ context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlags("sign", stderr)
	keysDir := fs.String("keys", "", "directory holding the private keys (*.key, PKCS#8 PEM); every one signs")
	in := fs.String("in", "top10k.txt", "the list to sign; the signature is written to `FILE`.sig")
	if err := parse(fs, args, stderr); err != nil {
		return err
	}
	if *keysDir == "" {
		_, _ = fmt.Fprintln(stderr, "pwlist sign: --keys is required")
		return errUsage
	}
	// Sign only what is fit to publish: the checksum the build wrote
	// still matches, and the list parses -- which a sample does not.
	data, err := checkedList(*in)
	if err != nil {
		return err
	}
	paths, err := filepath.Glob(filepath.Join(*keysDir, "*.key"))
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		return fmt.Errorf("no *.key files in %s", *keysDir)
	}
	keys := make([]ed25519.PrivateKey, 0, len(paths))
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		k, err := listsig.ParsePrivateKey(raw)
		if err != nil {
			return fmt.Errorf("%s: %w", filepath.Base(p), err)
		}
		keys = append(keys, k)
	}
	sig, err := listsig.Sign(data, keys)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(*in+".sig", sig, 0o644); err != nil {
		return err
	}
	for _, k := range keys {
		_, _ = fmt.Fprintf(stdout, "pwlist sign: signed %s with key %s\n", *in, listsig.KeyID(k.Public().(ed25519.PublicKey)))
	}
	return nil
}

func cmdVerify(_ context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlags("verify", stderr)
	keysDir := fs.String("keys", "", "directory holding the trusted public keys (*.pub), e.g. blocklist/keys")
	in := fs.String("in", "top10k.txt", "the list to verify, with `FILE`.sha256 and FILE.sig beside it")
	if err := parse(fs, args, stderr); err != nil {
		return err
	}
	if *keysDir == "" {
		_, _ = fmt.Fprintln(stderr, "pwlist verify: --keys is required")
		return errUsage
	}
	data, err := verifiedList(*in, *keysDir)
	if err != nil {
		return err
	}
	l, _ := blocklist.Parse(data) // checkedList parsed it already
	_, _ = fmt.Fprintf(stdout, "pwlist verify: %s is good: %d hashes, built %s\n", *in, l.Len(), l.Built().Format(time.RFC3339))
	return nil
}

// verifiedList is checkedList plus the signature beside the list,
// checked against the public keys (*.pub) in keysDir.
func verifiedList(path, keysDir string) ([]byte, error) {
	data, err := checkedList(path)
	if err != nil {
		return nil, err
	}
	ring, err := readPublicKeys(keysDir)
	if err != nil {
		return nil, err
	}
	sig, err := os.ReadFile(path + ".sig")
	if err != nil {
		return nil, err
	}
	if err := listsig.Verify(data, sig, ring); err != nil {
		return nil, err
	}
	return data, nil
}

// checkedList reads a list, checks it against the .sha256 beside it and
// parses it. The .sha256 must name the list's own file.
func checkedList(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	sumFile, err := os.ReadFile(path + ".sha256")
	if err != nil {
		return nil, err
	}
	if string(sumFile) != sha256Line(data, filepath.Base(path)) {
		return nil, fmt.Errorf("%s.sha256 does not match %s", path, path)
	}
	if _, err := blocklist.Parse(data); err != nil {
		return nil, err
	}
	return data, nil
}

func readPublicKeys(dir string) (listsig.Keyring, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.pub"))
	if err != nil {
		return nil, err
	}
	keys := make([]ed25519.PublicKey, 0, len(paths))
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		k, err := listsig.ParsePublicKey(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Base(p), err)
		}
		keys = append(keys, k)
	}
	return listsig.NewKeyring(keys...)
}

var keyName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

func cmdKeygen(_ context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlags("keygen", stderr)
	out := fs.String("out", "", "directory to write NAME.key (private, 0600) and NAME.pub into")
	name := fs.String("name", "", "the key's name: lowercase letters, digits and dashes, e.g. pwlist-2026")
	if err := parse(fs, args, stderr); err != nil {
		return err
	}
	if *out == "" || !keyName.MatchString(*name) {
		_, _ = fmt.Fprintln(stderr, "pwlist keygen: --out is required, and --name must be lowercase letters, digits and dashes")
		return errUsage
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	privPEM, err := listsig.MarshalPrivateKey(priv)
	if err != nil {
		return err
	}
	pubPEM, err := listsig.MarshalPublicKey(pub)
	if err != nil {
		return err
	}
	privPath := filepath.Join(*out, *name+".key")
	pubPath := filepath.Join(*out, *name+".pub")
	// O_EXCL: never overwrite a key, which would lose it for good.
	if err := writeNew(privPath, privPEM, 0o600); err != nil {
		return err
	}
	if err := writeNew(pubPath, pubPEM, 0o644); err != nil {
		_ = os.Remove(privPath)
		return err
	}
	_, _ = fmt.Fprintf(stdout, "pwlist keygen: key id %s\n  private: %s (keep it off this repository; it goes in /etc/gauntlet-signing/ on the signing runner's host)\n  public:  %s (commit it under blocklist/keys/)\n",
		listsig.KeyID(pub), privPath, pubPath)
	return nil
}

func writeNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}
