#!/usr/bin/env python3
"""Enforce per-package Go coverage floors, and ratchet them upward.

Copied from birdcage's scripts/coverage-floor.py, unchanged except for
the two notes below that were specific to birdcage's own frontend and
guard scripts, which gauntlet has neither of.

This checks STATEMENT coverage: every percentage here and in
supply-chain/coverage-floors.yml is "how many statements ran at least
once". That is the only number Go's own tooling produces.

Do not read that as "branches are invisible" -- it is narrower than it
sounds, and the difference matters when deciding what this file does not
protect. An untaken branch IS caught, because a body that never runs is
uncovered statements: a function whose true path is never taken reports
66.7%, not 100%.

What statement coverage cannot see is a compound condition. `if a && b`
reports 100% having only ever run (true, true) and (false, true): `b` was
never independently decisive, and no number says so. That is the gap
MC/DC exists to close, and the reason DO-178C and IEC 61508 ask for it at
their highest levels rather than asking for a percentage.

Both claims above were tested against the real toolchain, not assumed.

So the owner's 70-85% band (birdcage issue #74, 2026-09-20) is read
against statements here. Gauntlet has no frontend and no branch-coverage
tool, so unlike birdcage there is no separate branch floor anywhere.

Per-package percentages are computed by attributing each block in the Go
coverage profile to the directory of its source file (the package), and
summing statement counts weighted the same way `go test`'s own per-package
summary line does: a package's coverage is (statements with count > 0) /
(statements). This was checked against `go tool cover -func`'s per-file
breakdown and against `go test`'s own "coverage: X% of statements" lines
for the same profile, on this repository, and matched to one decimal place
for every package -- see the commit message that introduced this script for
the comparison. It matches because `go test`'s default -coverpkg only
instruments the package under test, so nothing in the merged profile
belongs to any package other than the one whose tests produced it.

Rules enforced, each one a `problems` entry below:
  - a package below its floor: coverage regressed, or a floor was set wrong.
  - a package in the coverage profile but absent from the floors file: a new
    package must not slip in unmeasured -- adding its floor is a reviewed
    change to supply-chain/coverage-floors.yml, not something this script
    does silently.
  - a package sitting more than RATCHET_SLACK points ABOVE its floor: a floor
    that never rises is a target, not a ratchet. This is what makes it one.
    The constant carries the value and why it is set where it is; this
    docstring deliberately does not repeat the number, having already been
    wrong about it once.

Exit codes: 0 clean; 1 one of the rules above fired; 2 the profile or the
floors file could not be read or parsed (fail red, never quietly green).

Usage: coverage-floor.py <coverage.out> [floors.yml]
  floors.yml defaults to supply-chain/coverage-floors.yml, resolved relative
  to the current directory -- run this from the repository root.

YAML parsing: hand-rolled, not PyYAML, matching birdcage's own script.
coverage-floors.yml only ever has one flat `floors:` mapping of
`package: integer  # comment`, and a dozen lines of hand-parsing that shape
is simpler to read and audit than pulling in a parser for a format this
file never uses.
"""
import math
import os
import sys

TARGET_BAND = (70, 85)

# How far a package may drift above its floor before this job asks for the
# floor to be raised. Set deliberately loose.
#
# The ratchet only works if the floors track reality, so drift has to be
# caught. But the action that causes drift is somebody adding tests, and a
# check that fails the build for improving coverage teaches people to stop
# improving coverage -- or to switch the check off, which is the failure
# mode scripts/ci-e2e-guard.py exists to prevent. A tight value here
# punishes the good move: on a small package a single new test moves the
# percentage several points at once.
#
# Five points is the compromise: small improvements land without ceremony,
# and a package that has genuinely pulled ahead still gets its floor
# raised rather than quietly keeping a floor nobody has looked at in
# months. Raise this if it turns out to nag; do not remove it, or the
# floors rot and the ratchet becomes decoration.
RATCHET_SLACK = 5


def fail(code, message):
    print(f"coverage-floor: {message}", file=sys.stderr)
    raise SystemExit(code)


def find_module_prefix(start_dir):
    """The module path from the nearest go.mod above `start_dir`.

    Coverage-profile file paths are import paths (module path + package
    directory); floors.yml keys are plain package directories
    (`internal/db`, not `github.com/.../internal/db`). This strips the
    module path back off so the two line up.
    """
    d = os.path.abspath(start_dir)
    while True:
        candidate = os.path.join(d, "go.mod")
        if os.path.isfile(candidate):
            try:
                with open(candidate) as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("module "):
                            return line[len("module "):].strip()
            except OSError as err:
                fail(2, f"cannot read {candidate}: {err}")
            fail(2, f"{candidate} has no 'module' line")
        parent = os.path.dirname(d)
        if parent == d:
            fail(2, "no go.mod found above the current directory; run this "
                     "from the repository root")
        d = parent


def parse_profile(path, module_prefix):
    try:
        with open(path) as f:
            lines = f.readlines()
    except OSError as err:
        fail(2, f"cannot read coverage profile {path}: {err}")

    if not lines or not lines[0].startswith("mode:"):
        fail(2, f"{path} does not look like a Go coverage profile "
                 f"(expected a 'mode:' header line first)")

    prefix = module_prefix.rstrip("/") + "/"
    total = {}
    covered = {}
    for lineno, raw in enumerate(lines[1:], start=2):
        line = raw.strip()
        if not line:
            continue
        try:
            filepart, numstmt_s, count_s = line.rsplit(" ", 2)
            file_and_pos = filepart.split(":", 1)
            file = file_and_pos[0]
            numstmt = int(numstmt_s)
            count = int(count_s)
        except (ValueError, IndexError):
            fail(2, f"{path}:{lineno}: cannot parse coverage line: {line!r}")

        if not file.startswith(prefix):
            fail(2, f"{path}:{lineno}: {file!r} is not under module "
                     f"{module_prefix!r}")
        rel = file[len(prefix):]
        pkg = os.path.dirname(rel)
        total[pkg] = total.get(pkg, 0) + numstmt
        if count > 0:
            covered[pkg] = covered.get(pkg, 0) + numstmt

    if not total:
        fail(2, f"{path} has no coverage data after the 'mode:' header")
    return total, covered


def parse_floors(path):
    try:
        with open(path) as f:
            lines = f.readlines()
    except OSError as err:
        fail(2, f"cannot read floors file {path}: {err}")

    floors = {}
    in_block = False
    for lineno, raw in enumerate(lines, start=1):
        line = raw.rstrip("\n")
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not line[0].isspace():
            in_block = (stripped.rstrip() == "floors:")
            continue
        if not in_block:
            continue
        body = line.split("#", 1)[0].strip()
        if not body:
            continue
        if ":" not in body:
            fail(2, f"{path}:{lineno}: expected 'package: number', got "
                     f"{stripped!r}")
        key, _, value = body.partition(":")
        key = key.strip()
        # A double-quoted key, e.g. "": 91, is how the module's own root
        # package is written -- the coverage profile's package key is the
        # directory holding each source file relative to the module root,
        # and the root package's files (store.go, etc.) have no directory
        # component, so that key is "". This parser is hand-rolled, not a
        # real YAML reader (see the module docstring), so it has to be
        # taught this the same way real YAML already understands it.
        if len(key) >= 2 and key[0] == '"' and key[-1] == '"':
            key = key[1:-1]
        value = value.strip()
        try:
            floors[key] = int(value)
        except ValueError:
            fail(2, f"{path}:{lineno}: floor for {key!r} is not an integer: "
                     f"{value!r}")

    if not floors:
        fail(2, f"{path} has no 'floors:' mapping, or it is empty")
    return floors


def check(profile_path, floors_path):
    module_prefix = find_module_prefix(".")
    total, covered = parse_profile(profile_path, module_prefix)
    floors = parse_floors(floors_path)

    got = {}
    for pkg, stmts in total.items():
        got[pkg] = 100.0 * covered.get(pkg, 0) / stmts if stmts else 0.0

    problems = []
    for pkg in sorted(got):
        if pkg not in floors:
            problems.append(
                f"{pkg}: got {got[pkg]:.1f}%, no floor in {floors_path} -- "
                f"a new package must not slip in unmeasured; add a floor "
                f"for it there as a reviewed change.")
            continue
        floor = floors[pkg]
        if got[pkg] < floor:
            problems.append(f"{pkg}: got {got[pkg]:.1f}%, floor {floor}%")
        elif got[pkg] > floor + RATCHET_SLACK:
            raise_to = math.floor(got[pkg])
            problems.append(
                f"{pkg}: got {got[pkg]:.1f}%, floor {floor}% -- more than "
                f"{RATCHET_SLACK} points above its floor. Raise its floor "
                f"in {floors_path} to {raise_to} to lock in the gain.")

    if problems:
        print("coverage-floor: coverage ratchet failed:\n", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1

    band_lo, band_hi = TARGET_BAND
    in_band = sum(1 for f in floors.values() if band_lo <= f <= band_hi)
    debt = sum(1 for f in floors.values() if f < band_lo)
    print(f"coverage-floor: {len(floors)} package(s) checked, {in_band} "
          f"inside the {band_lo}-{band_hi}% band, {debt} carrying known "
          f"debt below it (including packages with no test files).")
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("usage: coverage-floor.py <coverage.out> [floors.yml]",
              file=sys.stderr)
        raise SystemExit(2)
    profile_arg = sys.argv[1]
    floors_arg = (sys.argv[2] if len(sys.argv) > 2
                  else os.path.join("supply-chain", "coverage-floors.yml"))
    raise SystemExit(check(profile_arg, floors_arg))
