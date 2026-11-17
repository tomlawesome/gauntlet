# Flakes

Checks that failed and then passed on unchanged code. One entry per
sighting; a third sighting of the same check gets an issue.

## lint:go: runner out of disk while restoring the cache

- 2026-10-03 · 9bb92c5 (preview → main, !25) · pipeline 2029, job
  30713, `lint:go` · `no space left on device` while extracting the Go
  cache, then `go build` read a truncated module file (`expected
  'package', found 'EOF'`). The same commit passed on !24. A retry
  (job 30721) passed. Cause is the shared `light` runner's disk, not
  this project.
