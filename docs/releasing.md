# Releasing

Gauntlet ships a tag, cut from CI. Nobody creates a `v*` tag by hand.

1. Bump `VERSION` (plain semantic version, e.g. `0.2.0`) and move the
   CHANGELOG's `[Unreleased]` entries under `[<version>] - <date>`, in an
   ordinary merge request to `dev`. A release is also gated on its
   release audit (the `security` issue for the version) being closed with
   evidence.
2. Once that merges, open the `dev` pipeline and press **release:version**.
   It refuses if the tag already exists, then **release:gitlab** creates
   the annotated tag `v<VERSION>` and the GitLab release at that commit.
   `release-cli` acts as whoever pressed the button, and `v*` tags are
   protected, so only the owner can cut one.
3. The tag's own pipeline runs `sync:mirror-to-github`, which pushes the
   tag object to `github.com/tomlawesome/gauntlet`. Check it arrived:
   `gh api repos/tomlawesome/gauntlet/git/ref/tags/v<VERSION>` should
   report object type `tag`, not `commit`.

Apps then take it with `go get github.com/tomlawesome/gauntlet@v<VERSION>`.
