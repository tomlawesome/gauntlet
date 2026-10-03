# Trusted signing keys for the common-password list

Each `*.pub` file here is the public half of an Ed25519 key that signs
the common-password list (#52, [ADR-0007](../../docs/adr/0007-common-password-list.md)).
It's a PEM `PUBLIC KEY` block (the standard public-key file format
`openssl` and most tools read), as `pwlist keygen` writes it. They are
compiled into gauntlet, and a list -- fetched by a `Refresher` or
embedded -- is accepted only when one of these keys signed it.

The first key is `pwlist-2026.pub` (owner, 2026-10-03). The owner
generates a pair somewhere private (`go run ./cmd/pwlist keygen --out
DIR --name NAME`, or `openssl genpkey -algorithm ed25519` and `openssl
pkey -pubout`), puts the private half on the signing runner's host under
`/etc/gauntlet-signing/`, and commits only `NAME.pub` here. A private
key never enters this repository.

Rotation: commit the new `.pub` beside the old one and release. Put the
new private key next to the old one on the runner, so the list is
signed by both. A release later, remove the old `.pub` and the old
private key. Every file here other than `*.pub` (this README) is
ignored.
