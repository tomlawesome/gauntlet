# Releasing

Gauntlet ships a tag, cut from CI. Nobody creates a `v*` tag by hand.

A release is cut on `main`, and only on `main` (#88, owner 2026-10-08:
"release is on main, dev and preview are not a release"). A new version
travels `dev` -> `preview` -> `main` by merge request, and the release
button exists only in `main`'s pipelines. A version that is on `dev` or
`preview` but not yet on `main` has not been released.

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

3. Once that merge request lands on `dev`, promote it to `preview`:
   open a merge request from `dev` to `preview`. Its pipeline runs every
   lint and test job, and `preview`'s own pipeline runs them all again
   once it lands. `preview` is the pre-release stage, the last stop
   before a release. Gauntlet has no jobs that run only on `preview`
   yet, so its bar is the same full set of lint and test jobs `dev`
   runs. Nothing is ever pushed straight to `preview` or `main`.

4. Once `preview`'s pipeline is green, open a merge request from
   `preview` to `main`. Merging it puts a merge commit on `main`, and
   `main`'s pipeline for that commit runs every lint and test job once
   more.

5. Click **CI/CD > Pipelines** and open `main`'s pipeline for that
   merge commit -- the newest row whose branch is `main`. Click
   **release:version**. It can only be pressed once every job in that
   pipeline's lint and test stages has passed. `dev` and `preview`
   pipelines have no release button at all.

   release:version refuses to cut a tag in four cases:
   - the tag already exists -- bump `VERSION` and merge again
   - `VERSION` isn't a plain three-part version, or doesn't sort above
     the newest tag already cut -- fix the `VERSION` file and merge
     again
   - the commit isn't the current tip of `main` -- you opened an old
     pipeline; open the pipeline for the newest commit on `main`
     instead
   - the common-password list in `blocklist/embedded/` is still the
     placeholder, or was built more than 90 days ago -- run
     `scripts/update-blocklist.sh` as in step 2 and merge again

   "Merge again" means the whole route: a merge request into `dev`,
   then steps 3 and 4 to bring it to `main`.

   Once release:version succeeds, **release:gitlab** runs by itself --
   there's no second button to press. It creates the tag `v<VERSION>`
   and the GitLab release at that commit, using release-cli (GitLab's
   tool for cutting a release from a CI job). The tag and release are
   created as whoever pressed release:version. `v*` tags are protected
   (a GitLab setting that limits who may create them), so only the owner
   can press the button.

   The version is released once this tag exists on `main`'s commit --
   not before.

6. Once release:gitlab creates the tag, its own pipeline runs
   **sync:mirror-to-github**, which pushes the tag to the public mirror
   at `github.com/tomlawesome/gauntlet`. It needs two project CI/CD
   variables, both protected, which only the owner sets:
   - `MIRROR_TO_GITHUB` = `true`: without it the job does not appear at
     all.
   - `GITHUB_MIRROR_SSH_KEY`: the private SSH key that may push to the
     mirror. Create it with type **File**, not the default Variable:
     the job reads the key from a file, so a plain Variable stops the
     job with `GITHUB_MIRROR_SSH_KEY must be a File-type CI/CD variable`
     before the key can reach the log. If the variable is missing, or the tag is not protected (a
     protected variable reaches only protected tags and branches), the
     job fails with
     `GITHUB_MIRROR_SSH_KEY is not set -- is v<VERSION> protected?`.

   Check the tag arrived:
   ```
   gh api repos/tomlawesome/gauntlet/git/ref/tags/v<VERSION> --jq .object.type
   ```
   - `tag` means it arrived correctly. GitLab makes release tags as
     annotated tags, which store their own message and author.
   - `commit` means only a bare pointer to the commit arrived, without
     the release message: the push went wrong. Do not announce the
     version yet -- once anyone fetches a tag through the public Go
     module proxy, the proxy records it for good. Read the
     sync:mirror-to-github job's log to see what was pushed.
   - a 404 means the tag hasn't reached GitHub yet -- give the sync job
     more time, or check that it ran.

7. Back-merge. Each promotion's merge commit lands only on the branch
   that received it, so `preview` is now behind `main`, and the next
   promotion would report the branches as out of step. Open a merge
   request from `main` to `preview` and merge it. Then do the same from
   `preview` to `dev` if GitLab shows `dev` as behind `preview`.
   Neither merge changes any files.

Apps then take it with `go get github.com/tomlawesome/gauntlet@v<VERSION>`.

v0.3.0 was tagged on a `dev` commit (e8b0009), before this order
existed. Its tag stays where it is -- a published tag is never moved.
It counts as released once `main` has that commit, through the usual
`dev` -> `preview` -> `main` merge requests.

## What the owner checks once (#88)

The release button moved from `dev`'s pipeline to `main`'s. Two GitLab
settings decide who may press it there; nothing in this repository can
change them.

- In
  [Settings > Repository > Protected branches](https://gitlab.tomlawson.io/ai/gauntlet/-/settings/repository),
  `main` is listed, with **Allowed to merge** set to the people who may
  release (Maintainers, or only you) and **Allowed to push and merge**
  set to **No one**. GitLab lets someone run a manual job on a
  protected branch only if they may merge into it, so this list is
  who can press release:version. Pushing set to No one keeps `main`
  reachable by merge request only.
- In the same page's **Protected tags**, `v*` still lists you under
  **Allowed to create**. That has not changed, but release:gitlab
  creates the tag as the person who pressed the button, so the two
  lists must agree.

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

**1. The signing key.** The `.key` file can sign a password list that
every application trusts: anyone who gets it can slip in a bad list.
So make it on a private machine, and never put it in the repository or
a chat.

On that machine, with this repository checked out, make a folder for
the key (keygen does not create one), then the key pair:
```
mkdir -m 700 ~/gauntlet-signing
go run ./cmd/pwlist keygen --out ~/gauntlet-signing --name pwlist-2026
```
This writes `pwlist-2026.key` (the private half, readable only by you)
and `pwlist-2026.pub` (the public half), and prints the key's id. It
refuses to overwrite a key that is already there.

If that machine has no Go, OpenSSL makes the same two files. The last
line makes the private half readable only by you:
```
openssl genpkey -algorithm ed25519 -out pwlist-2026.key
openssl pkey -in pwlist-2026.key -pubout -out pwlist-2026.pub
chmod 600 pwlist-2026.key
```
Commit only the `.pub`, as `blocklist/keys/pwlist-2026.pub`, through
an ordinary merge request.

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

**3. The key and the token on the runner host.** The runner host is
the machine where GitLab's runner program (`gitlab-runner`) runs the
CI jobs. Work there as root (the administrator account), because
`/etc` is only writable by root.

Each secret gets its own folder, owned by the runner's user, so each
runner can be given only its own secret. What each line below does:

- line 1 makes the two folders, which only the runner's user can open;
- line 2 copies the signing key into the first, readable only by that
  user;
- line 3 asks you to type the GitHub token and saves it into the
  second. It does not show the token on screen, and keeps it off the
  command line and out of shell history;
- line 4 gives the runner's user ownership of the token file.

```
install -d -m 0700 -o gitlab-runner -g gitlab-runner /etc/gauntlet-signing /etc/gauntlet-github
install -m 0600 -o gitlab-runner -g gitlab-runner /path/to/pwlist-2026.key /etc/gauntlet-signing/pwlist-2026.key
( umask 077 && IFS= read -r -s -p 'GitHub token: ' t && printf '%s\n' "$t" > /etc/gauntlet-github/token ); echo
chown gitlab-runner:gitlab-runner /etc/gauntlet-github/token
```

The runner's Docker is rootless: run by the `gitlab-runner` user
rather than by root. That brings two traps:

- Inside a job, "root" is really the `gitlab-runner` user, so a file
  owned by real root cannot be read there. That is why the lines above
  give each file to `gitlab-runner`.
- Rootless Docker only sees folders under `/etc` that existed when it
  started. A folder made afterwards is invisible to jobs until Docker
  restarts, even though the file is plainly there.

So restart that user's Docker once, now. **This stops any job running
on the host**, so do it when nothing important is running:
```
sudo -u gitlab-runner XDG_RUNTIME_DIR=/run/user/$(id -u gitlab-runner) \
  DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$(id -u gitlab-runner)/bus \
  systemctl --user restart docker
```
The two variables tell `systemctl` where the `gitlab-runner` user's
own service manager is; without them, running it from another account
fails with a connection error. Success prints nothing. Later reboots
need nothing: the folders exist before Docker starts.

The signing key has no password: `blocklist:sign` signs with nobody
present. What protects each secret is that only one runner mounts it.

**4. Two runners: `gauntlet-signing` and `gauntlet-publish`.** Each
holds one secret, so each must run only its one job: `blocklist:sign`
asks for a runner tagged `gauntlet-signing`, and `blocklist:publish`
for one tagged `gauntlet-publish`.

Create each in
[Settings > CI/CD](https://gitlab.tomlawson.io/ai/gauntlet/-/settings/ci_cd),
**Runners > New project runner**:

- **Tags**: `gauntlet-signing` for the first, `gauntlet-publish` for
  the second.
- **Run untagged jobs**: off, so no other job can land on a runner
  that holds a secret.
- **Protected**: on, so it refuses jobs from unprotected branches,
  which anyone with push access could write.
- **Lock to current projects**: on, so no other project can use it.

GitLab then shows a `gitlab-runner register` command. Run it on the
runner host, the same way that host's other runners were registered.
Leave `--token` off the command and paste the token when it asks, so
the token stays out of shell history. When it asks for an executor,
answer `docker` (each job then runs in its own Docker container).

Then add these lines to each runner's entry in `config.toml`, the
file where `gitlab-runner` keeps its runners (`gitlab-runner list`
prints its path):
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
What the lines do:

- `host` points the runner at the `gitlab-runner` user's own Docker.
  Replace `988` with that user's number, which `id -u gitlab-runner`
  prints.
- `volumes` shares the secret's folder into the job read-only (`ro`),
  so a job can read the secret but never change it.
- `environment` tells the publish job where the token file is. It
  holds a path, never the token. It must sit above the first
  `[runners.…]` heading in that entry (`[runners.cache]` or
  `[runners.docker]`): below one, TOML files it under that section and
  the job never sees it.

`gitlab-runner` notices the edited file by itself within a few seconds.
Each job fails at once if its secret file is not there.

**5. The schedule.** Each monthly run downloads 20-40 GB from HIBP and
takes about four hours, so check the host's bandwidth and runner
capacity first. Then, in
[Build > Pipeline schedules](https://gitlab.tomlawson.io/ai/gauntlet/-/pipeline_schedules),
create a schedule: description `blocklist`, target branch `dev`, a
monthly interval (for example `17 3 2 * *`, 03:17 UTC on the 2nd), and
a variable `BLOCKLIST_BUILD` = `true`.

Leave duplicate generic packages allowed under
[Settings > Packages and registries](https://gitlab.tomlawson.io/ai/gauntlet/-/settings/packages_and_registries):
each run uploads the list again to the `current` version, which is
overwritten every month by design, so refusing duplicates would fail
the second month's publish.

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
with the variable `BLOCKLIST_SAMPLE` = `true`. `blocklist:build` runs
over only the first 2,048 of the 1,048,576 groups HIBP serves its
hashes in (each group is the hashes sharing one 5-character start).
That is 1/512 of a full run, so roughly 40-80 MB in all. Its output is
stamped as a sample, which signing, publishing and every application
refuse.

On a branch other than `dev`, `preview` or `main`, `blocklist:build`
is the only job. On those three the lint and test jobs run as well, as
they do for every pipeline there.

### Rotating the signing key

1. Generate a new pair (step 1 above) and commit the new `.pub` beside
   the old one; release.
2. Put the new `.key` beside the old one in `/etc/gauntlet-signing/`,
   so each run signs with both. Applications on the previous release
   trust only the old key, so the list must carry both signatures for
   a while.
3. After the next release, once applications have upgraded, remove the
   old `.pub` and the old `.key`.

## Dependency updates (Renovate)

Renovate is a bot that checks for newer versions of what gauntlet
depends on (#63). Once a week it compares each pinned (fixed) version
with the newest release, and opens a merge request to `dev` for
whatever is behind. It watches:

- Go libraries, in `go.mod` and `gate/contracttest/go.mod`;
- Docker images in `.gitlab-ci.yml`: Go, Alpine, and Renovate's own;
- the tools CI installs at a fixed version: golangci-lint,
  govulncheck, gitleaks and go-licenses.

Every non-major update arrives together in one merge request; a major
one arrives on its own.

A security fix from the OSV advisory database (a public list of known
flaws) does not wait for Monday: a second schedule runs Renovate every
day for security fixes only, and the fix's merge request opens on the
first daily run after the advisory appears.

What it watches and why is in `renovate.json`, and the `renovate` job
in `.gitlab-ci.yml` runs it. The daily run adds
`renovate-security.json`, which turns every other update off.

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
only for a security fix, which Renovate allows at any hour. It also
leaves Monday's merge requests open: by default Renovate closes any of
its merge requests the current run did not produce, and this run
produces none of the ordinary ones. 06:37 is
after the Monday run's one-hour limit, so the two do not normally
overlap.

For the first run, give the schedule a second variable
`RENOVATE_DRY_RUN` = `full`. That Monday's `renovate` job then reports
what it would do and creates nothing: its log should end without
errors, with a `DRY-RUN: Would create branch` line for each merge
request it would open, and no warning about a dependency it could not
look up. Then delete `RENOVATE_DRY_RUN`; the next Monday's run opens
merge requests.

If the `renovate` job fails as soon as it starts, just after an update
to Renovate's own image was merged, undo that merge. Then, in
`renovate.json`, add the bad version to the `allowedVersions` pattern
of the `renovate/renovate` rule, which lists the versions to skip, so
it is not offered again.
