# Trusted signing keys for the common-password list

Each `*.pub` file here is the public half of an Ed25519 key that signs
the common-password list (#52, [ADR-0007](../../docs/adr/0007-common-password-list.md)):
a PEM `PUBLIC KEY` block (PKIX), as `pwlist keygen` writes it. They are
compiled into gauntlet, and a list -- fetched by a `Refresher` or
embedded -- is accepted only when one of these keys signed it.

**This directory has no key yet, so every list is refused.** The owner
generates the first pair (`go run ./cmd/pwlist keygen --out DIR --name
NAME`) somewhere private, puts the private half on the signing runner's
host under `/etc/gauntlet-signing/`, and commits only `NAME.pub` here.
A private key never enters this repository.

Rotation: commit the new `.pub` beside the old one and release; put the
new private key next to the old one on the runner, so the list is
signed by both; a release later, remove the old `.pub` and the old
private key. Every file here other than `*.pub` (this README) is
ignored.
