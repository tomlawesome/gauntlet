package passkey

import (
	"time"

	"github.com/tomlawesome/gauntlet/internal/spent"
)

// ceremonyLifetime is how long a ceremony may take from Begin to
// Finish: Begin seals Expires this far ahead, and Finish (and the
// library) refuse it after that. Five minutes, mikroview's number: long
// enough to unlock a phone or touch a security key, short enough that
// an abandoned ceremony does not leave a live one-shot ticket in a
// browser. gate's ceremony cookies carry the same Max-Age.
const ceremonyLifetime = 5 * time.Minute

// spentLoginChallenges remembers the challenge of every login ceremony
// that finished, until the ceremony would be refused anyway. The
// ceremony state rides in a sealed value the browser holds, so without
// this the server keeps nothing saying a ceremony was used, and an
// authenticator that always reports a sign count of zero (most platform
// passkeys) gives the counter nothing to catch a replay with: the same
// assertion could open a second session.
//
// FinishLogin claims with the sealed Expires as the forget time -- the
// same value open checks the ceremony against, on the same wall clock
// (internal/spent strips the monotonic reading) -- and the set holds it
// for one ceremonyLifetime past that (ruling S2 on #20), so the
// challenge is never forgotten while the ceremony would still be
// accepted, or while a request that read the clock before the expiry is
// still on its way, whatever the host's clock does.
//
// Claimed by FinishLogin only. A login is final inside FinishLogin --
// the signature is the proof -- so that is where its challenge is spent.
// Registrations are spent by gate, by the sealed cookie's hash, where
// the store decides (ruling S1 on #20): a claim inside FinishRegistration
// would fire before Store.AddPasskey had said yes.
var spentLoginChallenges = spent.New(ceremonyLifetime)
