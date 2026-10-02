package passkey

import (
	"errors"
	"fmt"
	"net"
	"net/url"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/tomlawesome/gauntlet"
)

// Config is what an application supplies to build its relying party.
type Config struct {
	// PublicURL is the address people reach the application on, from
	// the application's own setting (for example
	// "https://mikroview.home.lan:8443"). Its hostname becomes the
	// relying-party ID and scheme://host[:port] the one accepted origin;
	// a path, query or fragment is dropped. Never derived from a
	// request's Host header. Empty, not absolute, an IP-address host or
	// a non-secure scheme is not an error: New succeeds and Status says
	// why passkeys are off.
	PublicURL string
	// DisplayName is the product name the browser shows when a passkey
	// is created. Required.
	DisplayName string
}

// RelyingParty is the application's WebAuthn relying party, built once
// at startup by New. It implements gauntlet.PasskeyCeremony; its fields
// are deliberately unexported (ADR-0004 decision 2).
type RelyingParty struct {
	status gauntlet.PasskeyStatus
	rpID   string
	origin string
	// wa is nil unless status is ready.
	wa *webauthn.WebAuthn
}

var _ gauntlet.PasskeyCeremony = (*RelyingParty)(nil)

// Sealed ceremony state that cannot be used -- expired, tampered with,
// sealed for the other ceremony or by another process, or already used
// -- is reported by wrapping gauntlet.ErrPasskeyCeremonyInvalid, so gate
// can recognise it without importing this package. Which of those it
// was reaches only the log.
var (
	// ErrNotReady is returned by the ceremony methods while Status is
	// not gauntlet.PasskeyStatusReady.
	ErrNotReady = errors.New("passkey: relying party is not ready")
	// ErrNoUsablePasskey is returned by BeginLogin when the account
	// holds no passkey registered under the current relying-party ID.
	ErrNoUsablePasskey = errors.New("passkey: this account has no passkey registered for this relying party")
)

// New builds the relying party for cfg. A missing or unusable
// PublicURL is not an error -- it is a Status (unset, ip, insecure),
// because an application reached only by IP address must keep starting,
// with passkeys off and the reason reported (ADR-0004 decision 4). New
// returns an error only for an empty DisplayName, or when the WebAuthn
// library rejects a configuration this function believed well-formed,
// which would be a bug here rather than a bad setting.
//
// Policy is written out rather than left to the library's defaults,
// with the same result on the wire mikroview gets from those defaults
// (ADR-0004 decision 5): user verification preferred (asked for, never
// required -- this is a second factor behind a password, and requiring
// it would shut out security keys without a PIN), attestation "none"
// and no metadata service, resident-key preference unset. The library
// always requires user presence.
func New(cfg Config) (*RelyingParty, error) {
	if cfg.DisplayName == "" {
		return nil, errors.New("passkey: Config.DisplayName is required")
	}
	if cfg.PublicURL == "" {
		return &RelyingParty{status: gauntlet.PasskeyStatusUnset}, nil
	}
	u, err := url.Parse(cfg.PublicURL)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return &RelyingParty{status: gauntlet.PasskeyStatusUnset}, nil
	}
	hostname := u.Hostname()
	if net.ParseIP(hostname) != nil {
		return &RelyingParty{status: gauntlet.PasskeyStatusIP}, nil
	}
	// Browsers run a passkey ceremony only from a secure context: https,
	// or http on localhost. Every other scheme is refused for the same
	// reason.
	secure := u.Scheme == "https" || (u.Scheme == "http" && hostname == "localhost")
	if !secure {
		return &RelyingParty{status: gauntlet.PasskeyStatusInsecure}, nil
	}
	// An origin is only ever scheme://host[:port]: a path, query or
	// fragment on the URL is dropped rather than carried into it.
	origin := u.Scheme + "://" + u.Host

	wa, err := webauthn.New(&webauthn.Config{
		RPID:                  hostname,
		RPDisplayName:         cfg.DisplayName,
		RPOrigins:             []string{origin},
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			UserVerification: protocol.VerificationPreferred,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("passkey: constructing the WebAuthn relying party: %w", err)
	}
	return &RelyingParty{status: gauntlet.PasskeyStatusReady, rpID: hostname, origin: origin, wa: wa}, nil
}

// Status says whether passkeys work here, and why not when they do not.
func (rp *RelyingParty) Status() gauntlet.PasskeyStatus { return rp.status }

// RPID is the relying-party ID passkeys are registered under: the
// public URL's hostname. "" unless Status is ready.
func (rp *RelyingParty) RPID() string { return rp.rpID }

// Origin is the one origin ceremonies are accepted from. "" unless
// Status is ready.
func (rp *RelyingParty) Origin() string { return rp.origin }

func (rp *RelyingParty) ready() bool { return rp.status == gauntlet.PasskeyStatusReady }
