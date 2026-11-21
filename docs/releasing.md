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
   the list the last scheduled run published (from the GitHub repository's
   releases, which need no login) and checks its checksum, format and
   signature the way an application does. It refuses a list built more
   than 90 days ago. "Nothing to commit" just means the embedded list
   is already the newest.

   The same merge request also carries the release record,
   `docs/releases/v<version>.md`, which the readiness check (R1) requires
   before the first promotion. See "Before a promotion" and "The release
   record" below.

3. Once that merge request lands on `dev`, promote it to `preview`:
   open a merge request from `dev` to `preview`. Its pipeline runs every
   lint and test job, and `preview`'s own pipeline runs them all again
   once it lands. `preview` is the last stop before a release.
   It has no jobs of its own yet, so its pipeline runs the same full set
   of lint and test jobs as `dev`'s. Nothing is ever pushed straight to `preview` or `main`.

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
   - the commit is not the newest commit on `main` -- you opened an old
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
   **publish-gate**, which publishes the release to the public GitHub
   repository `github.com/tomlawesome/gauntlet` as one snapshot commit
   and an annotated tag (ai/agent-infra#147, #118). It scans every file
   for personal details and secrets first, and refuses on a finding.
   None of this repository's branches or history is sent; GitHub's
   `main` holds only the snapshot commits. It runs only for a protected
   `v*` tag.

   The first switch-over from the old mirror, and adding a reviewed
   binary file to `.publish-reviewed-files`, are in
   `scripts/publish-gate/README.md` in ai/agent-infra ("First
   switch-over", "Adding a reviewed binary file"). Its "Adopting it in a
   project" list assumes protected environments, which this GitLab
   (Community Edition) does not have: there a protected variable reaches
   every job in every protected pipeline. For this project, its steps 1
   to 4 and 6 are replaced by the five below, step 7 is already done in
   `.gitlab-ci.yml`, and steps 5 and 8 still apply: after the first run,
   set the `publish-gate` resource group to oldest first, and keep
   GitLab's own push mirror to GitHub switched off. The key is held the
   way the blocklist's secrets are (one secret per runner, ADR-0007):

   1. Protect tags `v*`, creatable by Maintainers only
      ([Settings > Repository > Protected tags](https://gitlab.tomlawson.io/ai/gauntlet/-/settings/repository)).
   2. Make a fresh deploy key on the runner host, straight into its
      folder, so the private half never leaves it:
      ```
      install -d -m 0700 -o gitlab-runner -g gitlab-runner /etc/gauntlet-publish-gate
      sudo -u gitlab-runner ssh-keygen -t ed25519 -N "" -C gauntlet-publish-gate -f /etc/gauntlet-publish-gate/key
      ```
      Add `/etc/gauntlet-publish-gate/key.pub` as a deploy key on
      [GitHub > Settings > Deploy keys](https://github.com/tomlawesome/gauntlet/settings/keys)
      with **Allow write access** ticked. Then restart the
      `gitlab-runner` user's Docker once, as in "The common-password list",
      "Setup the owner does once" step 3, so jobs can see the new folder.
      **This stops any job running on the host**, the monthly blocklist
      build included, so do it when nothing important is running.
   3. A third project runner, `gauntlet-publish-gate`, made like the two
      in that section's step 4: that tag, run untagged jobs
      off, protected on, locked to this project. In its `[[runners]]`
      entry in `config.toml`:
      ```toml
      environment = ["PUBLISH_GATE_SSH_KEY=/etc/gauntlet-publish-gate/key", "<the light runner's three CI_IMAGE_CACHE_* entries>"]
      [runners.docker]
        host = "unix:///run/user/988/docker.sock"
        volumes = ["/etc/gauntlet-publish-gate:/etc/gauntlet-publish-gate:ro", "<the light runner's private-details rules mount>", "/cache"]
      ```
      Replace `988` with `id -u gitlab-runner`'s number, as in that
      step. The `environment` line holds a path, never the key, and goes
      before any `[runners.…]` heading. Copy two things exactly from the
      `light` runner's entry: its three `CI_IMAGE_CACHE_*` entries (the
      job's image is pulled through the host's image cache, whose address
      lives only in `config.toml`; without them the job fails at image
      pull), and its private-details rules mount (the job scans with
      those rules at `/etc/private-details/rules.toml`).
   4. Let this project's jobs fetch the gate script: in ai/agent-infra,
      [Settings > CI/CD > Job token permissions](https://gitlab.tomlawson.io/ai/agent-infra/-/settings/ci_cd),
      add `ai/gauntlet`.
   5. Fence `main` and the `v*` tags on GitHub, after step 2 so the
      deploy key exists. The blocklist token needs Contents write for
      releases, which would also let it move `main` or a `v*` tag
      outside the publish gate. Two rulesets stop that, and the
      publish-gate deploy key (held only by that runner) is the one
      actor allowed past them. Open
      [Settings > Rules > Rulesets](https://github.com/tomlawesome/gauntlet/settings/rules),
      then for each ruleset below click **New ruleset**:
      1. **New branch ruleset**, named `protect main`. Set
         *Enforcement status* to **Active**. Under *Target branches*
         click **Add target > Include by pattern** and enter `main`.
         Under *Rules* tick **Restrict updates**, **Restrict
         deletions** and **Block force pushes**. Under *Bypass list*
         click **Add bypass**, choose **Deploy keys** and set it to
         **Always allow**. Click **Create**.
      2. **New tag ruleset**, named `protect release tags`. Set
         *Enforcement status* to **Active**. Under *Target tags* click
         **Add target > Include by pattern** and enter `v*`. Under
         *Rules* tick **Restrict creations**, **Restrict updates**,
         **Restrict deletions** and **Block force pushes**. Add the
         same bypass (**Add bypass > Deploy keys**, **Always allow**).
         Click **Create**.

      The `pwned-top10k-*` tags stay outside both rulesets, so the
      blocklist token still creates and replaces its releases. To
      check: with the blocklist token, try to push a `v*` tag; GitHub
      should refuse it. Then confirm the next publish-gate run still
      succeeds.

   No CI/CD variable holds the key, and no protected environment is
   needed; the job's `publish` environment only records deployments. If
   a `PUBLISH_GATE_SSH_KEY` variable exists under
   [Settings > CI/CD > Variables](https://gitlab.tomlawson.io/ai/gauntlet/-/settings/ci_cd)
   from the agent-infra README's steps, delete it, and remove that key
   from GitHub's deploy keys: a variable would win over the runner's
   path, so the job refuses to run while one exists. If the job's log
   says the key must be a "File-type CI/CD variable" or mentions the
   `publish` environment, that is the shared template's wording
   (ai/agent-infra#152): check the runner's `environment` line instead.

   During the first switch-over, move every old `pwned-top10k-*`
   release tag on GitHub, `pwned-top10k-current` included, to the first
   snapshot commit: they point at the old mirrored history, which the
   snapshot replaces. Move them; do not delete them, even though the
   README's step says to delete the listed old tags. A deleted tag turns
   its release into a draft, and apps fetching the current list get an
   error until the next monthly run. No run moves them for you:
   `blocklist:publish` sets `--target main` only when it creates a new
   release, and reuses an existing one without touching its tag. Force
   the tag ref, which keeps the release attached:
   ```
   gh api -X PATCH repos/tomlawesome/gauntlet/git/refs/tags/<tag> -f sha=<snapshot sha> -F force=true
   ```

   Check the tag arrived:
   ```
   gh api repos/tomlawesome/gauntlet/git/ref/tags/v<VERSION> --jq .object.type
   ```
   - `tag` means it arrived correctly. The gate pushes annotated tags,
     which store their own message and author.
   - `commit` means the tag arrived without its release message: the
     push went wrong. Do not announce the version yet. Go's public
     module download service (the Go module proxy) remembers any tag it
     has fetched permanently, so a wrong tag cannot be taken back. Read the
     publish-gate job's log to see what was pushed.
   - a 404 means the tag hasn't reached GitHub yet -- give the publish
     job more time, or check that it ran. A log ending
     `publish-gate: published <tag> as <short sha>` is healthy.

7. Bring `main` back into the other branches (a back-merge). Each
   promotion's merge commit lands only on the branch that received it:
   `main` now has one that `preview` lacks, and `preview` has one that
   `dev` lacks, so GitLab would show the branches as differing on the
   next promotion. Open a merge request from `main` to
   `preview` and merge it. Then do the same from `preview` to `dev` if
   GitLab shows `dev` as behind `preview`. Neither merge changes any
   files.

Apps then take it with `go get github.com/tomlawesome/gauntlet@v<VERSION>`.

v0.3.0 was tagged on a `dev` commit (e8b0009), before this order
existed. Its tag stays where it is -- a published tag is never moved.
It counts as released once `main` has that commit, through the usual
`dev` -> `preview` -> `main` merge requests.

## Before a promotion (#122)

Every promotion, `dev` -> `preview` and `preview` -> `main`, starts with the
release-readiness check. The `release_readiness` job runs it first in the
merge request's pipeline and nothing else starts until it ends; there is no
way to skip it. A `preview` -> `main` merge request opened by an agent gets
no pipeline of its own (GitLab runs one only for an author who may merge
into `preview`), so `preview`'s own pipeline runs the `main` check too, and
that pipeline is the one the merge request waits on (#134). A push of
`main`'s own commits back into `preview` passes it at once: there is
nothing to promote. Run the same script before opening the merge request, from a
checkout of the source branch with the target fetched:

```
scripts/release-readiness.sh preview   # dev -> preview
scripts/release-readiness.sh main      # preview -> main
```

It runs every check and ends with the full list. Each failure is a
`FAIL R<n>` line followed by a `do this:` line. Exit 1 means something
failed. Checks: R1 the release record, R2 `VERSION` is a new semantic
version above every tag, R3 `docs/api/auth.yaml`, R4 the CHANGELOG
section, R5 no `go.mod` `retract` covers the version, R6 the embedded
common-password list is fresh, R7 the target is an ancestor of the source
(otherwise: back-merge first), R8 the Go version of `GOLANG_IMAGE` equals
`go.mod`'s. A changed image digest is only a `WARN R8`. With a personal
`GITLAB_TOKEN` and `glab` it also checks the audit issue; in CI it says
"not checked here".

### The release record

Before each promotion the agent commits `docs/releases/v<VERSION>.md`: one
line per numbered step 1..N at the top of this guide, in order, and no
more. Read the whole guide first; the record names the guide it read. Copy
this template, replace every placeholder, and commit it as yourself with
`git commit --trailer "Signed-off-by: <Name>"`, so the `Signed-off-by:` line
is the commit's author name and its trailer. Never use `git commit -s`: it
adds an email, which the commit check refuses; the line is a name only:

```
# Release v<VERSION>

version: <VERSION>
guide-blob: <output of: git rev-parse HEAD:docs/releasing.md>
guide-commit: <output of: git log -1 --format=%H -- docs/releasing.md>
step 1: done: <issue or commit that shows it, e.g. #123 closed>
step 2: not-needed: <the owner's decision, with its date>
step 3: after-merge
Signed-off-by: <Name>
```

Each step line is `done: <evidence>`, `not-needed: <owner decision>` or
`after-merge`. An empty value, `TODO`, `TBD`, `n/a` or text left in angle
brackets fails R1. The `guide-commit:` line is required but informational:
its value is not compared. If the guide changes after the record is
written, `guide-blob` is stale and R1 fails: read the guide again and update
the record. The guide's own top-level steps must be numbered 1..N in order
with none missing (R1 fails otherwise), and a missing `docs/releasing.md`
on the source fails R1. This is a
checklist with a sign-off, not a signature: it stops a skipped or
part-read guide, a stale record and an anonymous one. False evidence it
cannot stop; the owner reads the record when approving.

### What the script does not check

| Step | Who | How |
| --- | --- | --- |
| Audit issue closed (step 1) | The agent cites the issue as #N in the record; the owner confirms | Checked only locally with a personal token; CI prints "not checked here" |
| Secret-holding runners online; `publish-gate` first switch-over | The owner | See "What the owner checks once" below and the publish-gate notes |
| Approval of the promotion merge request | The owner | A green job never replaces it |

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

Two more keep the Renovate tokens safe ("Dependency updates", "Setup
the owner does once" step 4):

- In
  [Settings > CI/CD > Variables](https://gitlab.tomlawson.io/ai/gauntlet/-/settings/ci_cd),
  **Minimum role to use pipeline variables** reads **Owner**.
- Every entry in
  [Build > Pipeline schedules](https://gitlab.tomlawson.io/ai/gauntlet/-/pipeline_schedules)
  is owned by you.

## The common-password list

`blocklist.Embedded()` and `blocklist.Refresher` provide the 10,000
most common passwords in the Pwned Passwords list from Have I Been
Pwned (HIBP), stored as SHA-1 hashes (fixed-length one-way
fingerprints, so the list does not contain the passwords themselves) (#52,
[ADR-0007](adr/0007-common-password-list.md); an ADR is an
architecture decision record, kept in docs/adr/). The monthly
`blocklist` pipeline schedule rebuilds the list from HIBP, signs it,
and publishes it to this project's package
registry and then to releases on the public GitHub repository, where
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

This token can also move `main` and `v*` tags, so the owner fences
them with GitHub rulesets: see release step 6 (the sub-step "Fence
`main` and the `v*` tags on GitHub").

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
  holds a path, never the token. Put it before any `[runners.…]`
  heading in that entry (`[runners.cache]` or `[runners.docker]`). If
  it comes after one, TOML reads it as part of that section instead and
  the job does not get it.

`gitlab-runner` notices the edited file by itself within a few seconds.
Each job fails at once if its secret file is not there.

**5. The schedule.** Each monthly run downloads 20-40 GB from HIBP and
takes about four hours, so check the host's bandwidth and runner
capacity first. Then, in
[Build > Pipeline schedules](https://gitlab.tomlawson.io/ai/gauntlet/-/pipeline_schedules),
create a schedule: description `blocklist`, target branch `main`, a
monthly interval (for example `17 3 2 * *`, 03:17 UTC on the 2nd), and
a variable `BLOCKLIST_BUILD` = `true`. The target is `main`, not `dev`,
so that only promoted code runs beside the GitHub token. A change to
`pwlist` therefore reaches the monthly build only after the next
promotion to `main`.

Leave the setting that allows uploading a file with the same name again
(duplicate generic packages) switched on, under
[Settings > Packages and registries](https://gitlab.tomlawson.io/ai/gauntlet/-/settings/packages_and_registries).
Each month's run replaces the previous list under the version name
`current`, by design, so blocking re-uploads would make the second
month's publish fail.

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
with the variable `BLOCKLIST_SAMPLE` = `true`. HIBP splits its hashes
into 1,048,576 groups, each sharing the same first 5 characters. In a
sample run `blocklist:build` fetches only the first 2,048 groups.
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
- Docker images in `.gitlab-ci.yml`: Go, Alpine, Renovate's own,
  release-cli and Trivy (check a new Trivy digest's signature by hand
  before merging it; `.gitlab-ci.yml` says why);
- the tools CI installs at a fixed version: golangci-lint,
  govulncheck, gitleaks and go-licenses.

Updates that keep the same first version number (for example 1.4 to
1.5) arrive together in one merge request; an update that changes it
(1.x to 2.0) arrives on its own.

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

Nothing runs until these five steps are done, and an assistant cannot
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

**3. The tokens on their own runner.** On this GitLab (Community
Edition) a protected CI/CD variable reaches every job in every
protected pipeline, so the tokens are held the way the publish gate's
key is in step 6 of the release steps at the top of this page,
sub-steps 2 and 3 (one secret per runner, ADR-0007):

1. On the runner host, from a root shell (`sudo -i`: `/etc` is
   writable only by root), put the two tokens in files, straight from
   the token pages, never through chat or a command line. Renovate's image
   runs as user 12021, not root, and on the runner's rootless Docker
   that user is a different host user from `gitlab-runner`: the first
   number in `gitlab-runner`'s line of `/etc/subuid`, plus 12020. The
   folder and files belong to that user, or the job cannot read them:
   ```
   u=$(( $(awk -F: '$1 == "gitlab-runner" { print $2 }' /etc/subuid) + 12020 ))
   install -d -m 0700 -o "$u" -g "$u" /etc/gauntlet-renovate
   ```
   Then, in the same root shell, create `gitlab-token` holding the GitLab token and
   `github-token` holding the GitHub token in that folder (an editor,
   paste, save), and lock them:
   ```
   chown "$u:$u" /etc/gauntlet-renovate/gitlab-token /etc/gauntlet-renovate/github-token
   chmod 0400 /etc/gauntlet-renovate/gitlab-token /etc/gauntlet-renovate/github-token
   ```
   The job checks both files are readable before it starts Renovate.
   Restart the `gitlab-runner` user's Docker once, as in "The
   common-password list", "Setup the owner does once" step 3, so jobs
   can see the new folder. **This stops any job running on the host**,
   so do it when nothing important is running.
2. Register a project runner, `gauntlet-renovate`, made like the
   others in that section's step 4: that tag, run untagged jobs off,
   protected on, locked to this project. In its `[[runners]]` entry in
   the runner config, `/etc/gitlab-runner/config.toml`:
   ```toml
   [runners.docker]
     host = "unix:///run/user/988/docker.sock"
     volumes = ["/etc/gauntlet-renovate:/etc/gauntlet-renovate:ro", "/cache"]
   ```
   Replace `988` with `id -u gitlab-runner`'s number, as in that step.
   Copy the `light` runner's three `CI_IMAGE_CACHE_*` environment
   entries too, if the `renovate` image is pulled through the host's
   image cache there. The mount holds the files, never the tokens in
   `config.toml`.
3. Delete any `RENOVATE_TOKEN` and `GITHUB_COM_TOKEN` CI/CD variables
   if they exist
   ([Settings > CI/CD > Variables](https://gitlab.tomlawson.io/ai/gauntlet/-/settings/ci_cd)).
   The `renovate` job refuses to run while either one is present.

**4. Pipeline variables for the owner only.** In
[Settings > CI/CD > Variables](https://gitlab.tomlawson.io/ai/gauntlet/-/settings/ci_cd),
set **Minimum role to use pipeline variables** to **Owner** and save.
(The same from a shell, run by the owner:
`glab api -X PUT projects/56 -f ci_pipeline_variables_minimum_override_role=owner`.)
This is what keeps the tokens safe (#138). A schedule's or a manual
run's variables reach the runner's own git fetch and the image's
startup before any job script runs, so no check in the `renovate`
job can stop a hostile one; the job's own check only catches a
mistaken variable of yours. Then open
[Build > Pipeline schedules](https://gitlab.tomlawson.io/ai/gauntlet/-/pipeline_schedules),
confirm every schedule there is yours, and delete any other: GitLab
does not re-check schedules that already exist against the new
setting.

From then on only you can start a gauntlet pipeline with variables:
the common-password list's sample runs (`BLOCKLIST_SAMPLE`),
publish-gate dry runs, and any agent run that passes `KEY=VALUE`.
Anyone else gets "Insufficient permissions to set pipeline
variables"; agents hand those runs to you.

**5. The schedules.** In
[Build > Pipeline schedules](https://gitlab.tomlawson.io/ai/gauntlet/-/pipeline_schedules),
create a schedule: description `renovate`, target branch `dev`, cron
`7 5 * * 1` with cron timezone **London** (05:07 every Monday), and a
variable `RENOVATE` = `true`. The time matters: `renovate.json` lets
Renovate open merge requests only between 05:00 and 06:15 London time
on a Monday, so a run at any other time finds nothing it may do. The
variable switches on the `renovate` job, and it is the only job this
schedule's pipeline runs.

Then create the daily schedule for security fixes: description
`renovate-security`, target branch `dev`, cron `37 6 * * *` with cron
timezone **London** (06:37 every day), and two variables, `RENOVATE` =
`true` and `RENOVATE_SECURITY_ONLY` = `true`. The second variable makes
the job add `renovate-security.json`, so this run opens a merge request
only for a security fix, which Renovate allows at any hour. It also
keeps Monday's merge requests open. Normally Renovate closes any of its
merge requests that the run in progress did not recreate, and this
daily run would recreate none of the Monday ones. 06:37 is after the
Monday run's one-hour time limit (the `renovate` job stops after one
hour, so a run started at 05:07 is over by about 06:07), so the two do
not normally overlap.

For the first run, give the schedule a second variable
`RENOVATE_DRY_RUN` = `full`. That Monday's `renovate` job then reports
what it would do and creates nothing: its log should end without
errors, with a `DRY-RUN: Would create branch` line for each merge
request it would open, and no warning about a dependency it could not
look up. Then delete `RENOVATE_DRY_RUN`; the next Monday's run opens
merge requests.

If the `renovate` job fails as soon as it starts, just after an update
to Renovate's own image was merged, undo that merge. Then edit
`renovate.json`: in the rule for `renovate/renovate`, add the bad
version to the `allowedVersions` pattern. It starts with `!`, so every
version it matches is skipped, and Renovate stops proposing it.
