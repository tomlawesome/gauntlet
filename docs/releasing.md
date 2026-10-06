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

   release:version refuses to cut a tag in four cases:
   - the tag already exists -- bump `VERSION` and merge again
   - `VERSION` isn't a plain three-part version, or doesn't sort above
     the newest tag already cut -- fix the `VERSION` file and merge
     again
   - the commit isn't the current tip of `dev` -- you opened an old
     pipeline; open the pipeline for the newest commit on `dev` instead
   - the common-password list in `blocklist/embedded/` is still the
     placeholder, or was built more than 90 days ago -- run
     `scripts/update-blocklist.sh` as in step 2 and merge again

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

Before the setup below was done there was no real list:
`blocklist/embedded/` held a placeholder, `Embedded()` blocked nothing,
and release:version refused to tag. The first list was embedded from
the run of 2026-10-03.

### Setup the owner does once

None of this can be done by an assistant: it needs root on the runner
host, a private key, a GitHub token and project settings.

**1. The signing key.** On a private machine, with this repository
checked out:
```
go run ./cmd/pwlist keygen --out ~/gauntlet-signing --name pwlist-2026
```
This writes `pwlist-2026.key` (the private half, mode 0600) and
`pwlist-2026.pub`, and prints the key's id. OpenSSL makes the same two
files if you would rather not run Go there:
```
openssl genpkey -algorithm ed25519 -out pwlist-2026.key
openssl pkey -in pwlist-2026.key -pubout -out pwlist-2026.pub
chmod 600 pwlist-2026.key
```
Commit only the `.pub`, as
`blocklist/keys/pwlist-2026.pub`, through an ordinary merge request.
The `.key` never enters the repository or chat.

**2. The GitHub token.** Create a
[fine-grained personal access token](https://github.com/settings/personal-access-tokens/new)
with *Repository access: Only select repositories* →
`tomlawesome/gauntlet`, and *Repository permissions → Contents: Read
and write* (releases need it; nothing else is needed).

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
Use the runner user's real uid in place of `988`. The `environment`
line must sit above the first `[runners.…]` heading in that entry
(`[runners.cache]` or `[runners.docker]`): below one, TOML files it
under that section and the job never sees it. The
`environment` line tells the job where the token file is; it holds a
path, never the token. Each job fails at once if its file is not there.

**5. The schedule.** In
[Build > Pipeline schedules](https://gitlab.tomlawson.io/ai/gauntlet/-/pipeline_schedules),
create a schedule: description `blocklist`, target branch `dev`, a
monthly interval (for example `17 3 2 * *`, 03:17 UTC on the 2nd), and
a variable `BLOCKLIST_BUILD` = `true`.

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

## Dependency updates (Renovate)

Once a week Renovate compares everything gauntlet pins with its newest
release and opens a merge request to `dev` for whatever is behind
(#63): the Go modules in `go.mod` and `gate/contracttest/go.mod`, the
Go and Alpine images and Renovate's own image in `.gitlab-ci.yml`, and
the tools CI installs at fixed versions (golangci-lint, govulncheck,
gitleaks, go-licenses). Every non-major update arrives together in one
merge request; a major one arrives on its own. A security fix from the
OSV advisory database does not wait for Monday: a second schedule runs
Renovate every day for security fixes only, and the fix's merge request
opens on the first daily run after the advisory appears. What it
watches and why is in `renovate.json`; the `renovate` job in
`.gitlab-ci.yml` runs it; both are copied from orbit's. The daily run
adds `renovate-security.json`, which turns every other update off.

Renovate only opens merge requests. Each one runs the normal pipeline
and is merged by hand like any other. The apidiff tool is the one pin
it does not watch: `renovate.json` says why.

### Setup the owner does once

Nothing runs until these four steps are done, and an assistant cannot
do any of them: they create credentials and change project settings.

**1. A GitLab token for Renovate.** In
[Settings > Access tokens](https://gitlab.tomlawson.io/ai/gauntlet/-/settings/access_tokens),
add a project access token: name `renovate`, role **Developer**, scope
**api**, and an expiry with a calendar reminder. Renovate acts on the
project with this token: `api` is what lets it push its branches and
open merge requests (a `read_api` token could look but never write),
and Developer is the lowest role that can push a branch. A project
token is limited to this one project.

**2. A GitHub token for reading release notes.** Create a
[fine-grained personal access token](https://github.com/settings/personal-access-tokens/new)
with *Repository access: Public repositories* and no permissions at
all. Most of gauntlet's modules and tools live on github.com, and
Renovate reads their tags and release notes there. GitHub allows only
60 unauthenticated requests an hour, so without a token a run stops
partway through; with no permissions the token can read only what
anyone can.

**3. The two tokens as CI/CD variables.** In
[Settings > CI/CD > Variables](https://gitlab.tomlawson.io/ai/gauntlet/-/settings/ci_cd),
add `RENOVATE_TOKEN` (the GitLab token) and `GITHUB_COM_TOKEN` (the
GitHub token), each with **Masked** and **Protected** ticked. Masked
keeps the value out of job logs. Protected hands it only to pipelines
on protected branches: the schedule below runs on `dev`, which is
protected, and no merge request pipeline ever sees either token.

**4. The schedules.** In
[Build > Pipeline schedules](https://gitlab.tomlawson.io/ai/gauntlet/-/pipeline_schedules),
create a schedule: description `renovate`, target branch `dev`, cron
`7 5 * * 1` with cron timezone **London** (05:07 every Monday), and a
variable `RENOVATE` = `true`. The time matters: `renovate.json` lets
Renovate open merge requests only between 05:00 and 06:15 London time
on a Monday, so a run at any other time finds nothing it may do. The
variable is what picks the `renovate` job: every other job stays out of
scheduled pipelines.

Then create the daily schedule for security fixes: description
`renovate-security`, target branch `dev`, cron `37 6 * * *` with cron
timezone **London** (06:37 every day), and two variables, `RENOVATE` =
`true` and `RENOVATE_SECURITY_ONLY` = `true`. The second variable makes
the job add `renovate-security.json`, so this run opens a merge request
only for a security fix, which Renovate allows at any hour. 06:37 is
after the Monday run's one-hour limit, so the two do not normally
overlap.

For the first run, give the schedule a second variable
`RENOVATE_DRY_RUN` = `full`. That Monday's `renovate` job then reports
what it would do and creates nothing: its log should end without
errors, with a `DRY-RUN: Would create branch` line for each merge
request it would open, and no warning about a dependency it could not
look up. Then delete `RENOVATE_DRY_RUN`; the next Monday's run opens
merge requests.

If a run fails at start-up after Renovate bumped its own image, revert
that bump and add the version to the `renovate/renovate` rule in
`renovate.json`.
