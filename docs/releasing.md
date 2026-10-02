# Releasing

Gauntlet ships a tag, cut from CI. Nobody creates a `v*` tag by hand.

1. Check the release audit is finished. Every version has a release
   audit: an issue labelled `security` in that version's milestone. It
   must be closed, with a comment that links each finding to its fix.
   CI does not check this -- the releaser does, before starting
   anything else below.

2. Once the audit is closed, open an ordinary merge request to `dev`
   that bumps `VERSION` to the next version -- a plain three-part
   version like `0.2.0`, three numbers separated by dots, no leading
   zeros -- sets `info.version` in `docs/api/auth.yaml` to the same
   value (the contract tests fail if the two differ), and moves the
   CHANGELOG's `[Unreleased]` entries under `[<version>] - <date>`.

3. Once that merge request lands on `dev`, click **CI/CD > Pipelines**
   and open the pipeline for the merge commit -- it's the top row.
   Click **release:version**. It can only be pressed once every job in
   the lint and test stages has passed.

   release:version refuses to cut a tag in three cases:
   - the tag already exists -- bump `VERSION` and merge again
   - `VERSION` isn't a plain three-part version, or doesn't sort above
     the newest tag already cut -- fix the `VERSION` file and merge
     again
   - the commit isn't the current tip of `dev` -- you opened an old
     pipeline; open the pipeline for the newest commit on `dev` instead

   Once release:version succeeds, **release:gitlab** runs by itself --
   there's no second button to press. It creates the tag `v<VERSION>`
   and the GitLab release at that commit, using release-cli (GitLab's
   tool for cutting a release from a CI job). The tag and release are
   created as whoever pressed release:version. `v*` tags are protected,
   so only the owner can press the button.

4. Once release:gitlab creates the tag, its own pipeline runs
   **sync:mirror-to-github**, which pushes the tag to the public mirror
   at `github.com/tomlawesome/gauntlet`. This job only appears when the
   project's `MIRROR_TO_GITHUB` CI/CD variable is set to `true` -- only
   the owner sets it.

   Check the tag arrived:
   ```
   gh api repos/tomlawesome/gauntlet/git/ref/tags/v<VERSION> --jq .object.type
   ```
   - `tag` means it arrived correctly: GitLab creates releases as
     annotated tags, which carry their own object instead of just
     pointing at a commit
   - `commit` means a plain commit ref landed instead of the annotated
     tag -- the push went wrong
   - a 404 means the tag hasn't reached GitHub yet -- give the sync job
     more time, or check that it ran

Apps then take it with `go get github.com/tomlawesome/gauntlet@v<VERSION>`.
