# Releasing

Gauntlet ships a tag, cut from CI. Nobody creates a `v*` tag by hand.

1. Check the release audit is finished. Every version has a release
   audit: an issue labelled `security` in that version's milestone. It
   must be closed, with a comment that links each finding to its fix.
   CI does not check this -- the releaser does, before starting
   anything else below.

2. Once the audit is closed, open an ordinary merge request to `dev`
   that does three things:
   - Bumps `VERSION` to the next version -- a plain three-part version
     like `0.2.0`, three numbers separated by dots, no leading zeros.
   - Sets `info.version` in `docs/api/auth.yaml` to the same value (the
     contract tests fail if the two differ).
   - Moves the CHANGELOG's `[Unreleased]` entries under
     `[<version>] - <date>`.

   The same merge request carries the newest common-password list
   (#52): run
   ```
   scripts/update-blocklist.sh
   ```
   and commit what it changes under `blocklist/embedded/`. It fetches
   the list the last scheduled run published (from the GitHub mirror's
   releases, which need no login) and checks its checksum, format and
   signature the way an application does. It refuses a list built more
   than 90 days ago. "Nothing to commit" just means the embedded list
   is already the newest.

3. Once that merge request lands on `dev`, click **CI/CD > Pipelines**
   and open the pipeline for the merge commit -- it's the top row.
   Click **release:version**. It can only be pressed once every job in
   the lint and test stages has passed.

   <!-- screenshot: the pipeline's job list with release:version highlighted, ready to press -->

   release:version refuses to cut a tag in four cases:
   - the tag already exists -- bump `VERSION` and merge again
   - `VERSION` isn't a plain three-part version, or doesn't sort above
     the newest tag already cut -- fix the `VERSION` file and merge
     again
   - the commit isn't the current tip of `dev` -- you opened an old
     pipeline; open the pipeline for the newest commit on `dev` instead
   - the common-password list in `blocklist/embedded/` is still the
     placeholder, or was built more than 90 days ago -- run
     `scripts/update-blocklist.sh` as in step 2 and merge again.
     v0.2.0 alone may ship the placeholder, with no built-in list,
     because the first signed list did not exist yet (owner,
     2026-10-02); every later version is refused again

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

## The common-password list

`blocklist.Embedded()` and `blocklist.Refresher` serve the SHA-1
hashes of the 10,000 most prevalent passwords in the Pwned Passwords
list from Have I Been Pwned (HIBP) (#52,
[ADR-0007](adr/0007-common-password-list.md); an ADR is an
architecture decision record, kept in docs/adr/). The monthly
`blocklist` pipeline schedule rebuilds the list from HIBP, signs it,
and publishes it to this project's package
registry and then to releases on the public GitHub mirror, where
applications fetch it. Step 2 above copies the published list into
each release.

Until the setup below is done there is no real list:
`blocklist/embedded/` holds a placeholder, and `Embedded()` blocks
nothing. Every fetched list is refused for want of a trusted key, and
release:version refuses to tag (v0.2.0 excepted, step 3 above).

### Setup the owner does once

None of this can be done by an assistant: it needs root on the runner
host, a private key, a GitHub token and project settings.

**1. The signing key.** On a private machine, with this repository
checked out:
```
go run ./cmd/pwlist keygen --out ~/gauntlet-signing --name pwlist-2026
```
This writes `pwlist-2026.key` (the private half, mode 0600) and
`pwlist-2026.pub`, and prints the key's id. Commit only the `.pub`, as
`blocklist/keys/pwlist-2026.pub`, through an ordinary merge request.
The `.key` never enters the repository or chat.

**2. The GitHub token.** Create a
[fine-grained personal access token](https://github.com/settings/personal-access-tokens/new)
with *Repository access: Only select repositories* →
`tomlawesome/gauntlet`, and *Repository permissions → Contents: Read
and write* (releases need it; nothing else is needed).

<!-- screenshot: the fine-grained token form with repository access and the Contents: Read and write permission set -->

Give it an
expiry and a calendar reminder: when it expires, the GitHub copy stops
updating and applications keep the last list. Do not turn on GitHub's
*immutable releases* for this repository: the
`pwned-top10k-current` release's files are replaced every run.

**3. The key and the token on the runner host.** As root, put each in
its own directory, owned by the runner's user (two directories, so
each runner mounts only its own secret):
```
install -d -m 0700 -o gitlab-runner -g gitlab-runner /etc/gauntlet-signing /etc/gauntlet-github
install -m 0600 -o gitlab-runner -g gitlab-runner /path/to/pwlist-2026.key /etc/gauntlet-signing/pwlist-2026.key
( umask 077 && IFS= read -r -s -p 'GitHub token: ' t && printf '%s\n' "$t" > /etc/gauntlet-github/token ); echo
chown gitlab-runner:gitlab-runner /etc/gauntlet-github/token
```
`read -s` keeps the token off the command line and out of shell
history. These are birdcage's steps
([its docs/releasing.md](https://gitlab.tomlawson.io/ai/birdcage/-/blob/dev/docs/releasing.md),
setup §2-3) with gauntlet's names, and its two traps apply here too.
First: rootless Docker runs the job container's root as the runner's
own host user, not real root, so a file left owned by root would be
unreadable inside the job -- the commands above already chown each
secret to `gitlab-runner` for that reason. Second: rootless Docker
only sees directories under `/etc` that existed when its daemon
started, so a directory created afterwards is invisible to it until a
restart, even though the file is plainly there.

Restart that user's Docker once after creating the directories above
(this stops any job running on the host):
```
sudo -u gitlab-runner XDG_RUNTIME_DIR=/run/user/$(id -u gitlab-runner) \
  DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$(id -u gitlab-runner)/bus \
  systemctl --user restart docker
```
The signing key has no password: `blocklist:sign` signs with nobody
present. What protects each secret is that only one runner mounts it.

**4. Two runners: `gauntlet-signing` and `gauntlet-publish`.**
Register two project runners on that host for this project, each with
the docker executor. Set each **protected** (so it refuses jobs from
unprotected branches) and **locked to this project**, with "run
untagged jobs" off. In their `config.toml` entries:
```toml
# in the gauntlet-signing runner's [[runners]] entry (blocklist:sign only)
[runners.docker]
  host = "unix:///run/user/988/docker.sock"
  volumes = ["/etc/gauntlet-signing:/etc/gauntlet-signing:ro", "/cache"]
```
```toml
# in the gauntlet-publish runner's [[runners]] entry (blocklist:publish only)
environment = ["GAUNTLET_GITHUB_RELEASE_TOKEN_FILE=/etc/gauntlet-github/token"]
[runners.docker]
  host = "unix:///run/user/988/docker.sock"
  volumes = ["/etc/gauntlet-github:/etc/gauntlet-github:ro", "/cache"]
```
Use the runner user's real uid in place of `988`. The
`environment` line tells the job where the token file is; it holds a
path, never the token. Each job fails at once if its file is not there.

**5. The schedule.** In
[Build > Pipeline schedules](https://gitlab.tomlawson.io/ai/gauntlet/-/pipeline_schedules),
create a schedule: description `blocklist`, target branch `dev`, a
monthly interval (for example `17 3 2 * *`, 03:17 UTC on the 2nd), and
a variable `BLOCKLIST_BUILD` = `true`.

<!-- screenshot: the pipeline schedule form with the description, target branch, interval and BLOCKLIST_BUILD variable filled in -->

Each run downloads 20-40 GB
from HIBP over about four hours. Optionally, under
[Settings > Packages and registries](https://gitlab.tomlawson.io/ai/gauntlet/-/settings/packages_and_registries),
refuse duplicate generic packages, so a dated GitLab version can never
be uploaded twice.

**6. The first run.** Press the schedule's play button. The pipeline
has three jobs: `blocklist:build`, `blocklist:sign` and
`blocklist:publish`. When all three pass, check that
[the `pwned-top10k-current` release](https://github.com/tomlawesome/gauntlet/releases/tag/pwned-top10k-current)
holds `top10k.txt`, `top10k.txt.sha256` and `top10k.txt.sig`, then run
`scripts/update-blocklist.sh` (step 2 above), commit
`blocklist/embedded/` -- the placeholder is removed -- and merge. That
is the first real list.

### Trying the build without publishing

From any branch, [run a pipeline](https://gitlab.tomlawson.io/ai/gauntlet/-/pipelines/new)
with the variable `BLOCKLIST_SAMPLE` = `true`. Only `blocklist:build`
runs, over the first 2,048 prefixes (a few MB from HIBP); its output
is marked as a sample, which nothing will sign, publish or accept.

### Rotating the signing key

Generate a new pair (step 1) and commit the new `.pub` beside the old
one; release. Put the new `.key` beside the old one in
`/etc/gauntlet-signing/`, so each run signs with both. A release later,
remove the old `.pub` and the old `.key`.
