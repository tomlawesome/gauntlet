# Trusted signing keys for the common-password list

Each `*.pub` file here is the public half of a signing key (Ed25519, a
standard signature method) that signs the common-password list (#52,
[ADR-0007](../../docs/adr/0007-common-password-list.md)). The signing
key is a pair: the private half makes a signature, the public half
checks it. The file is a PEM `PUBLIC KEY` block (PEM is a standard text format for
keys that `openssl` and most tools can read), as `pwlist keygen` writes it.

A signature proves the list came from the holder of the private key and
was not changed since. gauntlet is built with only these public keys
inside it, and it accepts a list only if it was signed by the matching
private key of one of them -- whether it is the copy built into a
release or one an application downloads while running, using a
`Refresher` (which fetches a newer list while the app runs).

## Where the private half lives

The first key is `pwlist-2026.pub`. The owner generates a pair on a
private machine, puts the private half (`NAME.key`) on the signing
runner's host under `/etc/gauntlet-signing/`, and commits only
`NAME.pub` here. The signing runner is the build machine that signs each
new list automatically.

Why the split: anyone holding the private half can sign a list that
every application will trust, so it stays on that one machine and never
enters this repository or a chat. The public half is safe to publish:
applications use it only to check signatures.

The full steps, with the commands, are in
[docs/releasing.md](../../docs/releasing.md), "Setup the owner does
once", step 1.

## Rotating a key

1. Add the new public key (`.pub`) next to the old one, and publish a
   release.
2. Put the new private key next to the old one on the runner, so each
   list is signed with both. Applications on the older release trust
   only the old key, so for one release the list carries both
   signatures and old and new applications both accept it.
3. In the release after that, once applications have upgraded, remove
   the old `.pub` and the old private key.

## Never put a private key in this folder

Gauntlet builds in only the `*.pub` files from this folder, so nothing
else here is compiled into a program built with gauntlet. A `.gitignore`
rule also tells Git to ignore everything except `*.pub`, `README.md` and
itself, so a private key left here by mistake will not be saved to the
repository or shipped. Still, keep it elsewhere: the ignore rule is a
safety net, not a place to store one.
