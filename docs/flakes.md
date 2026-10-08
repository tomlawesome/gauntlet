# Flakes

Checks that failed and then passed on unchanged code. One entry per
sighting; a third sighting of the same check gets an issue.

## gate: TestPendingLoginCodecRefusesTamperedCiphertext

- 2026-09-27 · 8aa9894 (feature/login-library, !1) · pipeline 1757,
  `test:go` · `got <nil>, want errPendingLoginInvalid`. The test edited
  the last base64 character of the sealed cookie; that character's low
  bits are padding the decoder ignores, so some edits changed no byte.
  Reproduced 2 in 300 local runs. **Fixed** in the same branch: the test
  now flips a bit of the decoded bytes (2000/2000 passes).

## lint:go: runner out of disk while restoring the cache

- 2026-10-03 · 9bb92c5 (preview → main, !25) · pipeline 2029, job
  30713, `lint:go` · `no space left on device` while extracting the Go
  cache, then `go build` read a truncated module file (`expected
  'package', found 'EOF'`). The same commit passed on !24. A retry
  (job 30721) passed. Cause is the shared `light` runner's disk, not
  this project.

## gate: TestSSORolesDowngradeAuditsNotifiesAndEndsOtherSessions

- 2026-10-07 · fbe315e (fix/v0.3.0-audit, local check list) ·
  `oidc_handler_test.go:1230: 0 role notices, want 1`. Passed alone and
  300 times in a row (`-race -count=300 -run TestSSORoles`). Cause: the
  role-change notice is sent in the background and the test's
  `roleNotices` helper read the recorder without waiting, as the other
  notice helpers do. **Fixed** in the same branch: the helper waits for
  `notifying` first. Not reproduced, so the fix is unproven by a failure.
