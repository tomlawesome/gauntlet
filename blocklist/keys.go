package blocklist

import (
	"crypto/ed25519"
	"embed"
	"fmt"
	"io/fs"
	"path"
	"strings"
	"sync"

	"github.com/tomlawesome/gauntlet/internal/listsig"
)

// The public keys a list must be signed by: every blocklist/keys/*.pub,
// compiled in, so trust travels with the release and an application
// has nothing to configure. A rotation is a commit to that directory
// and a release (blocklist/keys/README.md). Only *.pub is embedded, so
// a stray file there -- a private key, say -- is never compiled into an
// application (#87); the folder's .gitignore keeps it out of Git too.
//
//go:embed keys/*.pub
var keysFS embed.FS

// trustedKeys is the keyring built from keysFS once. An error -- a
// .pub file that does not parse -- leaves verification with no keys, so
// it refuses everything; TestCommittedKeysParse keeps such a file from
// ever being tagged.
var trustedKeys = sync.OnceValues(func() (listsig.Keyring, error) {
	return loadKeys(keysFS, "keys")
})

func loadKeys(fsys fs.FS, dir string) (listsig.Keyring, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("blocklist: read %s: %w", dir, err)
	}
	var keys []ed25519.PublicKey
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".pub") {
			continue
		}
		data, err := fs.ReadFile(fsys, path.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("blocklist: read %s: %w", e.Name(), err)
		}
		k, err := listsig.ParsePublicKey(data)
		if err != nil {
			return nil, fmt.Errorf("blocklist: %s: %w", e.Name(), err)
		}
		keys = append(keys, k)
	}
	return listsig.NewKeyring(keys...)
}
