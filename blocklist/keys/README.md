# Trusted signing keys for the common-password list

Each `*.pub` file here is the public half of an Ed25519 key that signs
the common-password list (#52, [ADR-0007](../../docs/adr/0007-common-password-list.md)).
It's a PEM `PUBLIC KEY` block (the standard public-key file format
`openssl` and most tools read), as `pwlist keygen` writes it.

A signature proves the list came from the holder of the private key and
was not changed since. These public keys (and only they) are compiled into gauntlet,
and a list is accepted only when one of them signed it -- whether it
is the copy built into a release or one an application downloads while
running (with a `Refresher`).

## Where the private half lives

The first key is `pwlist-2026.pub`. The owner generates a pair on a
private machine, puts the private half (`NAME.key`) on the signing
runner's host under `/etc/gauntlet-signing/`, and commits only
`NAME.pub` here. The signing runner is the CI machine that signs each
new list.

Why the split: anyone holding the private half can sign a list that
every application will trust, so it stays on that one machine and never
enters this repository or a chat. The public half is safe to publish:
applications use it only to check signatures.

The full steps, with the commands, are in
[docs/releasing.md](../../docs/releasing.md), "Setup the owner does
once", step 1.

## Rotating a key

1. Commit the new `.pub` beside the old one, and release.
2. Put the new private key next to the old one on the runner, so each
   list is signed with both. Applications on the older release trust
   only the old key, so for one release the list carries both
   signatures and old and new applications both accept it.
3. In the release after that, once applications have upgraded, remove
   the old `.pub` and the old private key.

## Never put a private key in this folder

Gauntlet embeds only the `*.pub` files here, so nothing else in this
folder is compiled into a program built with gauntlet. The folder's
`.gitignore` also keeps Git from tracking anything but `*.pub`,
`README.md` and itself, so a private key left here by mistake is neither
committed nor shipped. Still, keep it elsewhere: the ignore rule is a
safety net, not a place to store one.
