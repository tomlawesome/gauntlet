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
