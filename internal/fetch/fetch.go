// Package fetch holds the download rules blocklist and geoip share: the
// redirect policy their default HTTP clients follow and the spread put
// on their refresh intervals. Both packages fetch a file on a schedule
// from a host the operator configured; written out twice, a fix to one
// copy could miss the other (#90).
package fetch

import (
	"errors"
	"math/rand/v2"
	"net/http"
	"time"
)

// maxRedirects is how many redirects a download follows before giving
// up: enough for a release host that bounces through a CDN, few enough
// that a redirect loop ends quickly.
const maxRedirects = 5

// HTTPSRedirectsOnly is an http.Client CheckRedirect policy: follow up
// to five redirects, each to https. A download configured as https must
// not be quietly moved onto plain http by whoever answers it, where the
// file could be read or replaced on the way.
//
// Its errors carry no package prefix: the client returns them inside a
// *url.Error, and each caller adds its own name, so the message names
// the package the operator configured.
func HTTPSRedirectsOnly(req *http.Request, via []*http.Request) error {
	if req.URL.Scheme != "https" {
		return errors.New("refused a redirect away from https")
	}
	if len(via) >= maxRedirects {
		return errors.New("too many redirects")
	}
	return nil
}

// Jitter returns interval moved by up to a tenth either way, so many
// processes started together do not all download together.
func Jitter(interval time.Duration) time.Duration {
	tenth := int64(interval / 10)
	return interval + time.Duration(rand.Int64N(2*tenth+1)-tenth) //nolint:gosec // spreading load, not a secret
}
