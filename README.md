# gauntlet

A shared Go authentication library: local accounts, sessions, tokens,
OIDC and the HTTP middleware that gates them -- factored out of
[mikroview](https://github.com/tomlawesome/mikroview) so it and
[birdcage](https://gitlab.tomlawson.io/ai/birdcage) share one
implementation instead of two copies that drift apart.

**Status: pre-v0.1.0, not for use yet.** The API is still being built out
issue by issue against the design in [docs/design.md](docs/design.md);
nothing here has a stability guarantee until it tags.

See [docs/adr/0001-shared-auth-module.md](docs/adr/0001-shared-auth-module.md)
for why this module exists, and [SECURITY.md](SECURITY.md) for its threat
model.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
